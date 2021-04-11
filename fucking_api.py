from http.server import BaseHTTPRequestHandler, HTTPServer
import _thread
import time
import json

class MyServer(BaseHTTPRequestHandler):
  def __init__(self, data):
    self.data = data

  def __call__(self, *args, **kwargs):
    """ Handle a request """
    super().__init__(*args, **kwargs)

  def do_GET(self):
    if self.path.startswith('/classify'):
      global data
      self.send_response(200)
      self.send_header("Content-type", "text/json")
      self.end_headers()
      res_for_ip = 'by_ip=1' in self.path
      if res_for_ip:
        res = self.data.get(self.client_address[0], None)
        self.wfile.write(bytes(json.dumps(res, indent=2, sort_keys=True), "utf-8"))
      else:
        self.wfile.write(bytes(json.dumps(self.data, indent=2, sort_keys=True), "utf-8"))
    else:
      self.send_response(400)
      self.end_headers()
      self.wfile.write(bytes("naaa naaa naa", "utf-8"))


def create_server(data):
  hostName = "0.0.0.0"
  serverPort = 8249

  handler = MyServer(data)
  webServer = HTTPServer((hostName, serverPort), handler)
  print("Api started on http://%s:%s" % (hostName, serverPort))

  try:
      webServer.serve_forever()
  except KeyboardInterrupt:
      pass

  webServer.server_close()
  print("Server stopped.")


def run_api(data):
  t = _thread.start_new_thread( create_server, (data, ))