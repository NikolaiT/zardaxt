#/bin/bash
  
pkill -f "python tcp_fingerprint.py"

py=/root/.local/share/virtualenvs/satori-v7E0JF0G/bin/python

nohup $py tcp_fingerprint.py -i eth0 --classify > fp.out 2> fp.err < /dev/null &