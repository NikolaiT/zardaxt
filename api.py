from http.server import BaseHTTPRequestHandler, HTTPServer
import _thread
import json
import os
import traceback
from tcpip_fp_logging import log
from dune_client import incr
from urllib.parse import urlparse, parse_qs
from tcp_fingerprint_utils import makeOsGuess

API_KEY = os.environ.get('API_KEY', '')
if not API_KEY:
    raise Exception('InvalidAPIKeyException')

class ZardaxtApiServer(BaseHTTPRequestHandler):
    def __init__(self, fingerprints, timestamps):
        self.fingerprints = fingerprints
        self.timestamps = timestamps

    def __call__(self, *args, **kwargs):
        """ Handle a request """
        super().__init__(*args, **kwargs)

    def get_ip(self):
        ip = self.client_address[0]
        if ip == '127.0.0.1':
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
        self.wfile.write(bytes("Access Denied. Please query only endpoint /classify", "utf-8"))

    def send_text(self, payload):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(bytes(payload, "utf-8"))

    # infer the base operating system from the user-agent
    # and then infer the operating system from the TCP/IP
    # fingerprint and detect if there is a lie
    # {
    #   Windows: 2501,
    #   Android: 2501,
    #   iOS: 2501,
    #   Linux: 1149,
    #   'Mac OS': 2501,
    #   Ubuntu: 200,
    #   HarmonyOS: 11,
    #   android: 1,
    #   Fedora: 1
    # }
    def detect_os_mismatch(self, tcp_ip_fp):
        user_agent = self.get_user_agent()
        if user_agent:
            # get os by tcp ip fingerprint
            # Linux, macOS or Windows
            tcpip_os = {
              'linux': max(
                tcp_ip_fp["avg_score_os_class"]['Android']['avg'], 
                tcp_ip_fp["avg_score_os_class"]['Linux']['avg']
              ),
              'win': tcp_ip_fp["avg_score_os_class"]['Windows']['avg'],
              'mac': max(
                tcp_ip_fp["avg_score_os_class"]['iOS']['avg'], 
                tcp_ip_fp["avg_score_os_class"]['Mac OS']['avg']
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
        fpCopy = self.fingerprints.copy()
        fp_list = fpCopy.get(lookup_ip, None)
        if fp_list and len(fp_list) > 0:
            # return the newest fingerprint
            fp_res = fp_list[-1]
            classification = makeOsGuess(fp_res)
            classification['details']['num_fingerprints'] = len(fp_list)
            classification['details']['lookup_ip'] = lookup_ip
            classification['details']['client_ip'] = client_ip
            classification['details']['os_mismatch'] = self.detect_os_mismatch(classification)
            return self.send_json(classification)
        else:
            msg = {
                'lookup_ip': lookup_ip,
                'msg': 'no fingerprint for this IP ({} db entries)'.format(len(fpCopy)),
            }
            log(msg, 'api', onlyPrint=True)
            return self.send_json(msg)

    def handle_authenticated_lookup(self, client_ip):
        lookup_ip = self.get_query_arg('ip')
        if lookup_ip:
            log('Api Key provided. Looking up IP {}'.format(lookup_ip), 'api', onlyPrint=True)
            self.handle_lookup(client_ip, lookup_ip)
        else:
            return self.send_json(self.fingerprints.copy())

    def handle_lookup_by_client_ip(self, client_ip):
        log('No Api Key provided. Looking up client IP {}'.format(client_ip), 'api', onlyPrint=True)
        self.handle_lookup(client_ip, client_ip)

    def handle_uptime_interpolation(self, lookup_ip):
        timestampsCopy = self.timestamps.copy()
        res = []
        for key, value in timestampsCopy.items():
          if lookup_ip in key:
            if value.get('uptime_interpolation'):
              res.append(value)
        return self.send_json(res)

    def do_GET(self):
        client_ip = self.get_ip()
        incr('tcp_ip_fingerprint_public', client_ip)
        key = self.get_query_arg('key')

        try:
            if self.path.startswith('/classify'):
                log('Incoming API request from IP: {} with path: {}'.format(
                    client_ip, self.path), 'api', onlyPrint=True)
                if key and API_KEY == key:
                    return self.handle_authenticated_lookup(client_ip)
                else:
                    return self.handle_lookup_by_client_ip(client_ip)
            elif self.path.startswith('/uptime'):
              if key and API_KEY == key:
                lookup_ip = self.get_query_arg('ip')
                if not lookup_ip:
                  lookup_ip = client_ip
                return self.handle_uptime_interpolation(lookup_ip)
            elif self.path.startswith('/stats'):
                if key and API_KEY == key:
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


def create_server(fingerprints, timestamps):
    server_address = ('0.0.0.0', 8249)
    handler = ZardaxtApiServer(fingerprints, timestamps)
    httpd = HTTPServer(server_address, handler)
    log("TCP/IP Fingerprint API started on http://%s:%s" %
        server_address, 'api', level='INFO')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    log("TCP/IP Fingerprint API stopped.", 'api', level='INFO')


def run_api(fingerprints, timestamps):
    thread = _thread.start_new_thread(create_server, (fingerprints, timestamps))
    return thread
