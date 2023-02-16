# why use pythons own module it sucks
from datetime import datetime

def log(msg, module, onlyPrint=False, level='INFO'):
    msg = f'[{datetime.now()}] - {level} - {module} - {msg}'
    print(msg)
    if onlyPrint is False:
      with open('log/zardaxt.log', 'a') as logfile:
          logfile.write(msg + '\n')
      if level == 'ERROR':
        with open('log/zardaxt.err', 'a') as logfile:
            logfile.write(msg + '\n')
