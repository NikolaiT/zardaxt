#!/bin/bash
# (Re)start zardaxt on a server. Run it from cron, e.g. every 6 hours:
#   0 */6 * * * /bin/bash /root/zardaxt/restart.sh
# The API and the capture loop are one process; logs go to log/.
set -u
cd "$(dirname "$0")"
mkdir -p log
rm -f log/*

if [ -f /var/run/zardaxt.pid ]; then
  kill "$(cat /var/run/zardaxt.pid)" 2>/dev/null && echo "zardaxt pid $(cat /var/run/zardaxt.pid) killed."
  rm -f /var/run/zardaxt.pid
fi
pkill --echo -f "python src/zardaxt.py" || true
pkill --echo -f "python zardaxt.py" || true   # the pre-src/ layout; drop after 2026-10

PEW_CMD=$(command -v pew || echo "/root/.local/bin/pew")
/usr/bin/nohup "$PEW_CMD" in zardaxt python src/zardaxt.py zardaxt-server.json > log/nohup.out 2> log/nohup.err < /dev/null &
echo $! > /var/run/zardaxt.pid
echo "zardaxt pid $(cat /var/run/zardaxt.pid)"
