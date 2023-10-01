from http.server import BaseHTTPRequestHandler, HTTPServer
import _thread
import json
import socket
import traceback
from zardaxt_logging import log
from dune_client import incr
from urllib.parse import urlparse, parse_qs
from zardaxt_utils import make_os_guess


class HTTPServerIPv6(HTTPServer):
    address_family = socket.AF_INET6


class ZardaxtApiServer(BaseHTTPRequestHandler):
    def __init__(self, config, fingerprints, timestamps):
        self.config = config
        self.fingerprints = fingerprints
        self.timestamps = timestamps

    def __call__(self, *args, **kwargs):
        """ Handle a request """
        super().__init__(*args, **kwargs)

    def get_ip(self):
        ip = self.client_address[0]
        if ip in ['127.0.0.1', '::ffff:127.0.0.1', "::1"]:
            ip = self.headers.get('X-Real-IP')
        return ip

    def get_user_agent(self):
        return self.headers.get('user-agent')

    def get_query_arg(self, arg):
        query_components = parse_qs(urlparse(self.path).query)
        arg = query_components.get(arg, None)
        if arg and len(arg) > 0:
            return arg[0].strip()

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        BaseHTTPRequestHandler.end_headers(self)

    def send_json(self, payload):
        self.send_response(200)
        self.send_header("Content-type", "text/json")
        self.end_headers()
        self.wfile.write(
            bytes(json.dumps(payload, indent=2, sort_keys=True), "utf-8"))

    def deny(self):
        self.send_response(403)
        self.end_headers()
        self.wfile.write(
            bytes("Access Denied", "utf-8"))

    def send_text(self, payload):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(bytes(payload, "utf-8"))

    # infer the base operating system from the user-agent
    # and then infer the operating system from the TCP/IP
    # fingerprint and detect if there is a lie
    def detect_os_mismatch(self, tcp_ip_fp):
        user_agent = self.get_user_agent()
        if user_agent:
            # get os by tcp ip fingerprint
            # Linux, macOS or Windows
            tcpip_os = {
                'linux': max(
                    tcp_ip_fp["avg_score_os_class"]['Android'],
                    tcp_ip_fp["avg_score_os_class"]['Linux']
                ),
                'win': tcp_ip_fp["avg_score_os_class"]['Windows'],
                'mac': max(
                    tcp_ip_fp["avg_score_os_class"]['iOS'],
                    tcp_ip_fp["avg_score_os_class"]['Mac OS']
                ),
            }
            # get highest OS from TCP/IP fingerprint
            highestOS = max(tcpip_os, key=tcpip_os.get)
            userAgentOS = 'win'
            if 'Linux' in user_agent or 'Android' in user_agent:
                userAgentOS = 'linux'
            if 'Mac OS' in user_agent or 'iPhone' in user_agent:
                userAgentOS = 'mac'

            return highestOS != userAgentOS
        else:
            return None

    def handle_lookup(self, client_ip, lookup_ip):
        detailed = self.get_query_arg('detail') is not None
        fp_copy = self.fingerprints.copy()
        fp_list = fp_copy.get(lookup_ip, None)
        if fp_list and len(fp_list) > 0:
            # return the newest fingerprint
            fp_res = fp_list[-1]
            classification = make_os_guess(fp_res)
            classification['details']['num_fingerprints'] = len(fp_list)
            classification['details']['lookup_ip'] = lookup_ip
            classification['details']['client_ip'] = client_ip
            classification['details']['os_mismatch'] = self.detect_os_mismatch(
                classification)
            if detailed:
                return self.send_json(classification)
            else:
                return self.send_json({
                    "os_mismatch": classification['details']['os_mismatch'],
                    "lookup_ip": lookup_ip,
                    "perfect_score": classification['details']["perfect_score"],
                    "avg_score_os_class": classification["avg_score_os_class"]
                })
        else:
            msg = {
                'lookup_ip': lookup_ip,
                'msg': 'no fingerprint for this IP ({} fingerprints in memory)'.format(len(fp_copy)),
            }
            log(msg, 'api', onlyPrint=True)
            return self.send_json(msg)

    def handle_authenticated_lookup(self, client_ip):
        lookup_ip = self.get_query_arg('ip')
        if lookup_ip:
            log('Api Key provided. Looking up IP {}'.format(
                lookup_ip), 'api')
            self.handle_lookup(client_ip, lookup_ip)
        else:
            return self.send_json(self.fingerprints.copy())

    def handle_lookup_by_client_ip(self, client_ip):
        log('No Api Key provided. Looking up client IP {}'.format(
            client_ip), 'api', onlyPrint=True)
        self.handle_lookup(client_ip, client_ip)

    def do_GET(self):
        client_ip = self.get_ip()
        incr('tcp_ip_fingerprint_public', client_ip)
        key = self.get_query_arg('key')

        try:
            if self.path.startswith('/classify'):
                log('Incoming API request from IP: {} with path: {}'.format(
                    client_ip, self.path), 'api', onlyPrint=True)
                if key and self.config['api_key'] == key:
                    return self.handle_authenticated_lookup(client_ip)
                else:
                    return self.handle_lookup_by_client_ip(client_ip)
            if self.path.startswith('/all'):
                if key and self.config['api_key'] == key:
                    fpCopy = self.fingerprints.copy()
                    return self.send_json(fpCopy)
                else:
                    return self.deny(fpCopy)
            elif self.path.startswith('/stats'):
                if key and self.config['api_key'] == key:
                    fpCopy = self.fingerprints.copy()
                    return self.send_json({
                        'numIPs': len(fpCopy),
                        'numFingerprints': sum([len(value) for value in fpCopy.values()]),
                    })
            return self.deny()
        except Exception as e:
            traceback_str = ''.join(traceback.format_tb(e.__traceback__))
            msg = f'do_GET() failed: {e} with traceback {traceback_str}'
            log(msg, 'api', level='ERROR')
            return self.deny()


def create_server(config, fingerprints, timestamps):
    try:
        server_address = (config['api_server_ip'], config['api_server_port'])
        handler = ZardaxtApiServer(config, fingerprints, timestamps)
        httpd = HTTPServerIPv6(server_address, handler)
        log("TCP/IP Fingerprint (Zardaxt.py) API started on http://%s:%s" %
            server_address, 'api', level='INFO')
        httpd.serve_forever()
        httpd.server_close()
        log("TCP/IP Fingerprint API stopped.", 'api', level='INFO')
    except Exception as err:
        log("create_server() crashed with error: {} and stack: {}".format(
            err, traceback.format_exc()), 'api', level='ERROR')


def run_api(config, fingerprints, timestamps):
    thread = _thread.start_new_thread(
        create_server, (config, fingerprints, timestamps))
    return thread
