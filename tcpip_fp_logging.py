# why use pythons own module it sucks
from datetime import datetime


def log(msg, module, level='INFO'):
    msg = f'[{datetime.now()}] - {level} - {module} - {msg}\n'
    print(msg)
    with open('log/tcp_fingerprint.log', 'a') as logfile:
        logfile.write(msg)
    if level == 'ERROR':
      with open('log/tcp_fingerprint.err', 'a') as logfile:
          logfile.write(msg)
