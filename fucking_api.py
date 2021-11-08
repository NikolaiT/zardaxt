from http.server import BaseHTTPRequestHandler, HTTPServer
import _thread
import json
import traceback
from tcpip_fp_logging import log

# I know. Change this.
API_KEY='juvS44lvNkos78Vs'

class MyServer(BaseHTTPRequestHandler):
  def __init__(self, data):
    self.data = data

  def __call__(self, *args, **kwargs):
    """ Handle a request """
    super().__init__(*args, **kwargs)

  def end_headers (self):
    self.send_header('Access-Control-Allow-Origin', '*')
    BaseHTTPRequestHandler.end_headers(self)

  def do_GET(self):
    try:
      if self.path.startswith('/classify'):
        global data
        self.send_response(200)
        self.send_header("Content-type", "text/json")
        self.end_headers()
        res_for_ip = 'by_ip=1' in self.path
        if res_for_ip:
          ip = self.client_address[0]
          if ip == '127.0.0.1':
            ip = self.headers.get('X-Real-IP')
          res = self.data.get(ip, None)
          if res:
            res['ip'] = ip
            res['vpn_detected'] = False
            if 'fp' in res and 'tcp_mss' in res['fp']:
              res['vpn_detected'] = res['fp']['tcp_mss'] in [1240, 1361, 1289]
            self.wfile.write(bytes(json.dumps(res, indent=2, sort_keys=True), "utf-8"))
          else:
            self.wfile.write(bytes(json.dumps({'ip': ip, 'msg': 'no data'}, indent=2, sort_keys=True), "utf-8"))
        elif API_KEY in self.path:
          self.wfile.write(bytes(json.dumps(self.data, indent=2, sort_keys=True), "utf-8"))
      else:
        self.send_response(403)
        self.end_headers()
        self.wfile.write(bytes("Access Denied", "utf-8"))
    except Exception as e:
      traceback_str = ''.join(traceback.format_tb(e.__traceback__))
      log(f'do_GET() failed: {traceback_str}', level='ERROR')
      print(e)


def create_server(data):
  server_address = ('0.0.0.0', 8249)
  handler = MyServer(data)
  httpd = HTTPServer(server_address, handler)
  log("Api started on http://%s:%s" % server_address, level='INFO')

  try:
    httpd.serve_forever()
  except KeyboardInterrupt:
    pass

  httpd.server_close()
  log("Server stopped.", level='INFO')


def run_api(data):
  t = _thread.start_new_thread( create_server, (data, ))