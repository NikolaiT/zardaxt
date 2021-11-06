#/bin/bash

cd /root/tcp_fingerprint

if [ -f /var/run/tcp_fingerprint.pid ]
then
  kill `cat /var/run/tcp_fingerprint.pid`
  echo tcp_fingerprint pid `cat /var/run/tcp_fingerprint.pid` killed.
  rm -f /var/run/tcp_fingerprint.pid
else
  echo tcp_fingerprint not running.
fi
  
nohup pipenv run python tcp_fingerprint.py -i eth0 --classify > log/fp.out 2> log/fp.err < /dev/null &

# Write tcp_fingerprint's PID to a file
echo $! > /var/run/tcp_fingerprint.pid

echo tcp_fingerprint pid `cat /var/run/tcp_fingerprint.pid`