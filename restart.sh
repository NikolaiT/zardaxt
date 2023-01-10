#/bin/bash

cd /root/tcp_fingerprint

# purge log files for size reasons
rm /root/tcp_fingerprint/log/*;

if [ -f /var/run/tcp_fingerprint.pid ]
then
  kill `cat /var/run/tcp_fingerprint.pid`
  echo tcp_fingerprint pid `cat /var/run/tcp_fingerprint.pid` killed.
  rm -f /var/run/tcp_fingerprint.pid
else
  echo tcp_fingerprint not running.
fi

# kill everything just in case
pkill --echo -f "python tcp_fingerprint.py"

# I hate Python. It's a utterly broken language and ecosystem. JavaScript is 
# just so much better. Like I spent just too much time to figure this shit out:
# https://stackoverflow.com/questions/48990067/how-to-run-a-cron-job-with-pipenv

PATH=/usr/local/bin:$PATH

# https://stackoverflow.com/questions/40216311/reading-in-environment-variables-from-an-environment-file
set -a
source tcpip_fp.env
set +a

nohup /usr/local/bin/pipenv run python tcp_fingerprint.py -i eth0 > log/tcp_fp.out 2> log/tcp_fp.err < /dev/null &

# Write tcp_fingerprint's PID to a file
echo $! > /var/run/tcp_fingerprint.pid

echo tcp_fingerprint pid `cat /var/run/tcp_fingerprint.pid`