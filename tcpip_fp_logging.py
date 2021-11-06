# why use pythons own module it sucks
from datetime import datetime

def log(msg, level='INFO'):
  with open('log/tcp_fingerprint.log', 'a') as logfile:
    logfile.write(f'[{datetime.now()}] - {level} - {msg}\n')
