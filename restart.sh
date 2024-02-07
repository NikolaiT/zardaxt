#/bin/bash

current_hostname=$(hostname)
if [ "$current_hostname" == "vps-1a7d3b72" ]; then
    su -
fi

cd /root/zardaxt/;

# purge log files for size reasons
rm /root/zardaxt/log/*;

if [ -f /var/run/zardaxt.pid ]
then
  kill `cat /var/run/zardaxt.pid`
  echo "zardaxt pid `cat /var/run/zardaxt.pid` killed."
  rm -f /var/run/zardaxt.pid
else
  echo "zardaxt not running.";
fi

# kill everything just in case
pkill --echo -f "python zardaxt.py";

/usr/bin/nohup /usr/local/bin/pew in zardaxt python zardaxt.py zardaxt-server.json > log/nohup.out 2> log/nohup.err < /dev/null &

echo $! > /var/run/zardaxt.pid

echo zardaxt pid `cat /var/run/zardaxt.pid`