from http.server import BaseHTTPRequestHandler, HTTPServer
import _thread
import json
import os
import re
import traceback
from tcpip_fp_logging import log
from dune_client import incr
from urllib.parse import urlparse, parse_qs

API_KEY = os.environ.get('API_KEY', '')
if not API_KEY:
    raise Exception('InvalidAPIKeyException')

regex = re.compile(r'avg=(\d*\.\d*)')


def S(string):
    matches = regex.findall(string)
    if len(matches) > 0:
        return float(matches[0])


class MyServer(BaseHTTPRequestHandler):
    def __init__(self, data):
        self.data = data

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

    # infer the base operating system from the user-agent
    # and then infer the operating system from the TCP/IP
    # fingerprint and detect if there is a lie
    def detect_os_mismatch(self, tcp_ip_fp):
        user_agent = self.get_user_agent()
        # get os by tcp ip fingerprint
        # Linux, macOS or Windows
        tcpip_os = {
            'linux': max(S(tcp_ip_fp["avgScoreOsClass"]['Android']), S(tcp_ip_fp["avgScoreOsClass"]['Linux'])),
            'win': S(tcp_ip_fp["avgScoreOsClass"]['Windows']),
            'mac': max(S(tcp_ip_fp["avgScoreOsClass"]['iOS']), S(tcp_ip_fp["avgScoreOsClass"]['macOS'])),
        }
        # get highest OS from TCP/IP fingerprint
        highestOS = max(tcpip_os, key=tcpip_os.get)

        userAgentOS = 'win'
        if 'Linux' in user_agent or 'Android' in user_agent:
            userAgentOS = 'linux'
        if 'Mac OS' in user_agent or 'iPhone' in user_agent:
            userAgentOS = 'mac'

        return highestOS != userAgentOS

    def handle_authenticated_lookup(self, ip):
        lookup_ip = self.get_query_arg('ip')
        if lookup_ip:
            log('Api Key provided. Looking up IP {}'.format(lookup_ip), 'api')
            res = self.data.get(lookup_ip, None)
            if res:
                res['ip'] = ip
                res['lookup_ip'] = lookup_ip
                self.wfile.write(
                    bytes(json.dumps(res, indent=2, sort_keys=True), "utf-8"))
            else:
                msg = {
                    'lookup_ip': lookup_ip,
                    'msg': 'no fingerprint for this IP ({} db entries)'.format(len(self.data)),
                }
                self.wfile.write(
                    bytes(json.dumps(msg, indent=2, sort_keys=True), "utf-8"))
        else:
            self.wfile.write(
                bytes(json.dumps(self.data, indent=2, sort_keys=True), "utf-8"))

    def handle_lookup_by_client_ip(self, ip):
        log('No Api Key provided. Looking up client IP {}'.format(ip), 'api')
        res = self.data.get(ip, None)
        if res:
            res['ip'] = ip
            res['os_mismatch'] = self.detect_os_mismatch(res)
            self.wfile.write(
                bytes(json.dumps(res, indent=2, sort_keys=True), "utf-8"))
        else:
            msg = {
                'ip': ip,
                'msg': 'no fingerprint for this IP ({} db entries)'.format(len(self.data)),
            }
            self.wfile.write(
                bytes(json.dumps(msg, indent=2, sort_keys=True), "utf-8"))

    def do_GET(self):
        ip = self.get_ip()
        incr('tcp_ip_fingerprint_public', ip)

        try:
            if self.path.startswith('/classify'):
                self.send_response(200)
                self.send_header("Content-type", "text/json")
                self.end_headers()
                log('Incoming API request from IP: {} with path: {}'.format(
                    ip, self.path), 'api')
                key = self.get_query_arg('key')
                if key and API_KEY == key:
                    self.handle_authenticated_lookup(ip)
                else:
                    self.handle_lookup_by_client_ip(ip)
            else:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(
                    bytes("Access Denied. Please query only endpoint /classify", "utf-8"))
        except Exception as e:
            traceback_str = ''.join(traceback.format_tb(e.__traceback__))
            msg = f'do_GET() failed: {e} with traceback {traceback_str}'
            log(msg, 'api', level='ERROR')


def create_server(data):
    server_address = ('0.0.0.0', 8249)
    handler = MyServer(data)
    httpd = HTTPServer(server_address, handler)
    log("TCP/IP Fingerprint API started on http://%s:%s" %
        server_address, 'api', level='INFO')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    log("TCP/IP Fingerprint API stopped.", 'api', level='INFO')


def run_api(data):
    thread = _thread.start_new_thread(create_server, (data, ))
    return thread
