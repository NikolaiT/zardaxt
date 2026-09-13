"""Plain file logging into <repo>/log/, independent of the working directory."""
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / 'log'


def log(msg, module, onlyPrint=False, level='INFO'):
    line = f'[{datetime.now()}] - {level} - {module} - {msg}'
    print(line, flush=True)
    if onlyPrint:
        return
    try:
        LOG_DIR.mkdir(exist_ok=True)
        with open(LOG_DIR / 'zardaxt.log', 'a') as f:
            f.write(line + '\n')
        if level == 'ERROR':
            with open(LOG_DIR / 'zardaxt.err', 'a') as f:
                f.write(line + '\n')
    except OSError as err:  # a full disk must not take the capture down
        print(f'[log] cannot write {LOG_DIR}: {err}', flush=True)
