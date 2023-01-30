# why use pythons own module it sucks
from datetime import datetime


def log(msg, module, onlyPrint=False, level='INFO'):
    msg = f'[{datetime.now()}] - {level} - {module} - {msg}\n'
    print(msg)
    if onlyPrint is False:
      with open('log/tcp_fingerprint.log', 'a') as logfile:
          logfile.write(msg)
      if level == 'ERROR':
        with open('log/tcp_fingerprint.err', 'a') as logfile:
            logfile.write(msg)
