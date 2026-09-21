"""HTTP API next to the capture loop.

  GET /classify                         the caller's own fingerprint (X-Real-IP behind nginx)
  GET /classify?key=K&ip=1.2.3.4        any fingerprint in memory
  GET /classify?...&detail=1            with the raw fingerprint and per-OS scores
  GET /classify?...&ua=<user agent>     judge the SYN against this User-Agent instead
                                        of the request's own header
  GET /all?key=K                        every fingerprint in memory
  GET /stats?key=K

The relay verdict (`relay`) is present whenever a User-Agent is known and the
model is loaded; `os_mismatch` is derived from it, or from the OS scores when
there is no model.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import _thread
import json
import socket
import traceback
from urllib.parse import urlparse, parse_qs

from log import log
from dune_client import incr
from fingerprint import make_os_guess, MismatchModel, ua_os

APPLE = {'iOS', 'Mac OS'}


def os_class(name):
    return 'apple' if name in APPLE else name


def legacy_os_mismatch(avg_scores, user_agent):
    """Without a model: does the best-scoring OS class contradict the User-Agent?"""
    claimed = ua_os(user_agent)
    if not claimed:
        return None
    return os_class(max(avg_scores, key=avg_scores.get)) != os_class(claimed)


class HTTPServerIPv6(HTTPServer):
    address_family = socket.AF_INET6


class ApiHandler(BaseHTTPRequestHandler):
    def __init__(self, config, fingerprints, model):
        self.config = config
        self.fingerprints = fingerprints
        self.model = model

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def log_message(self, *args):  # quiet the default per-request stderr line
        pass

    def client_ip(self):
        ip = self.client_address[0]
        if ip in ('127.0.0.1', '::ffff:127.0.0.1', '::1'):
            ip = self.headers.get('X-Real-IP') or ip
        return ip

    def query(self, name):
        values = parse_qs(urlparse(self.path).query).get(name)
        return values[0].strip() if values else None

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def send_json(self, payload, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload, indent=2, sort_keys=True).encode('utf-8'))

    def deny(self):
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b'Access Denied')

    def classify(self, lookup_ip):
        fp_list = self.fingerprints.get(lookup_ip)
        if not fp_list:
            return self.send_json({'lookup_ip': lookup_ip, 'msg': f'no fingerprint for this IP ({len(self.fingerprints)} IPs in memory)'})
        fp = fp_list[-1]  # the newest SYN
        user_agent = self.query('ua') or self.headers.get('user-agent')
        result = make_os_guess(fp)
        relay = self.model.predict(fp, user_agent)
        details = result['details']
        details.update({'num_fingerprints': len(fp_list), 'lookup_ip': lookup_ip, 'client_ip': self.client_ip()})
        details['os_mismatch'] = relay['flagged'] if relay else legacy_os_mismatch(result['avg_score_os_class'], user_agent)
        if relay:
            result['relay'] = relay
        if self.query('detail') is None:
            slim = {'os_mismatch': details['os_mismatch'], 'lookup_ip': lookup_ip,
                    'perfect_score': details['perfect_score'], 'avg_score_os_class': result['avg_score_os_class']}
            if relay:
                slim['relay'] = relay
            return self.send_json(slim)
        return self.send_json(result)

    def do_GET(self):
        client_ip = self.client_ip()
        incr('tcp_ip_fingerprint_public', client_ip)
        authenticated = self.query('key') is not None and self.query('key') == self.config['api_key']
        try:
            if self.path.startswith('/classify'):
                lookup_ip = self.query('ip') if authenticated else None
                return self.classify(lookup_ip or client_ip)
            if not authenticated:
                return self.deny()
            if self.path.startswith('/all'):
                return self.send_json(dict(self.fingerprints))
            if self.path.startswith('/stats'):
                return self.send_json({
                    'numIPs': len(self.fingerprints),
                    'numFingerprints': sum(len(v) for v in self.fingerprints.values()),
                    'relayModel': self.model.loaded,
                })
            return self.deny()
        except Exception as err:
            log(f'request {self.path} failed: {err}\n{traceback.format_exc()}', 'api', level='ERROR')
            return self.send_json({'error': 'internal error'}, 500)


def serve(config, fingerprints):
    model = MismatchModel()
    address = (config['api_server_ip'], config['api_server_port'])
    try:
        httpd = HTTPServerIPv6(address, ApiHandler(config, fingerprints, model))
        log(f'API listening on http://[{address[0]}]:{address[1]}', 'api')
        httpd.serve_forever()
    except Exception as err:
        log(f'API server crashed: {err}\n{traceback.format_exc()}', 'api', level='ERROR')


def run_api(config, fingerprints):
    """Start the API in a background thread."""
    return _thread.start_new_thread(serve, (config, fingerprints))
