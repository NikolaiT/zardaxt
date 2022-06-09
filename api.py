from http.server import BaseHTTPRequestHandler, HTTPServer
import _thread
import json
import os
import traceback
from tcpip_fp_logging import log
from dune_client import incr
from urllib.parse import urlparse, parse_qs

API_KEY = os.environ.get('API_KEY', '')
if not API_KEY:
  raise Exception('InvalidAPIKeyException')

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

  def get_query_arg(self, arg):
    query_components = parse_qs(urlparse(self.path).query)
    arg = query_components.get(arg, None)
    if arg and len(arg) > 0:
      return arg[0].strip()

  def end_headers(self):
    self.send_header('Access-Control-Allow-Origin', '*')
    BaseHTTPRequestHandler.end_headers(self)

  def do_GET(self):
    ip = self.get_ip()
    incr('tcp_ip_fingerprint_public', ip)

    try:
      if self.path.startswith('/classify'):
        self.send_response(200)
        self.send_header("Content-type", "text/json")
        self.end_headers()
        ip = self.get_ip()
        log('Incoming API request from IP: {} with path: {}'.format(ip, self.path), 'api')
        key = self.get_query_arg('key')

        if key and API_KEY == key:
          lookup_ip = self.get_query_arg('ip')
          if lookup_ip:
            log('Api Key provided. Looking up IP {}'.format(lookup_ip), 'api')
            res = self.data.get(lookup_ip, None)
            if res:
              res['ip'] = ip
              res['lookup_ip'] = lookup_ip
              res['vpn_detected'] = False
              if 'fp' in res and 'tcp_mss' in res['fp']:
                res['vpn_detected'] = res['fp']['tcp_mss'] in [1240, 1361, 1289]
              self.wfile.write(bytes(json.dumps(res, indent=2, sort_keys=True), "utf-8"))
            else:
              msg = {
                'lookup_ip': lookup_ip, 
                'msg': 'no fingerprint for this IP ({} db entries)'.format(len(self.data)),
              }
              self.wfile.write(bytes(json.dumps(msg, indent=2, sort_keys=True), "utf-8"))
          else:
            self.wfile.write(bytes(json.dumps(self.data, indent=2, sort_keys=True), "utf-8"))
        else:
          log('No Api Key provided. Looking up client IP {}'.format(ip), 'api')
          res = self.data.get(ip, None)
          if res:
            res['ip'] = ip
            res['vpn_detected'] = False
            if 'fp' in res and 'tcp_mss' in res['fp']:
              res['vpn_detected'] = res['fp']['tcp_mss'] in [1240, 1361, 1289]
            self.wfile.write(bytes(json.dumps(res, indent=2, sort_keys=True), "utf-8"))
          else:
            msg = {
              'ip': ip, 
              'msg': 'no fingerprint for this IP ({} db entries)'.format(len(self.data)),
            }
            self.wfile.write(bytes(json.dumps(msg, indent=2, sort_keys=True), "utf-8"))
      else:
        self.send_response(403)
        self.end_headers()
        self.wfile.write(bytes("Access Denied. Please query only endpoint /classify", "utf-8"))
    except Exception as e:
      traceback_str = ''.join(traceback.format_tb(e.__traceback__))
      msg = f'do_GET() failed: {e} with traceback {traceback_str}'
      log(msg, 'api', level='ERROR')

def create_server(data):
  server_address = ('0.0.0.0', 8249)
  handler = MyServer(data)
  httpd = HTTPServer(server_address, handler)
  log("TCP/IP Fingerprint API started on http://%s:%s" % server_address, 'api', level='INFO')

  try:
    httpd.serve_forever()
  except KeyboardInterrupt:
    pass

  httpd.server_close()
  log("TCP/IP Fingerprint API stopped.", 'api', level='INFO')


def run_api(data):
  t = _thread.start_new_thread(create_server, (data, ))