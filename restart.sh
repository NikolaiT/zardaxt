#/bin/bash

cd /root/tcp_fingerprint

# purge log files for size reasons
rm /root/tcp_fingerprint/log/*;

if [ -f /var/run/zardaxt.pid ]
then
  kill `cat /var/run/zardaxt.pid`
  echo zardaxt pid `cat /var/run/zardaxt.pid` killed.
  rm -f /var/run/zardaxt.pid
else
  echo zardaxt not running.
fi

# kill everything just in case
pkill --echo -f "python zardaxt.py"

nohup /usr/local/bin/pipenv run python zardaxt.py > log/z.out 2> log/z.err < /dev/null &

echo $! > /var/run/zardaxt.pid

echo zardaxt pid `cat /var/run/zardaxt.pid`