#!/bin/bash
# Deploy zardaxt to one engine box and restart it:
#   ./deploy.sh env/de.env
#   ./deploy.sh env/east.env
set -euo pipefail
source "${1:-env/de.env}"   # LOCAL_DIR, BASE_DIR, SERVER, SSH_PRIV_KEY

# --delete keeps the box identical to this directory; excluded paths (config,
# logs, raw data) are never touched there.
rsync -az --delete --exclude-from "$LOCAL_DIR/exclude.txt" --info=stats0 --out-format='  %n' \
  -e "ssh -i $SSH_PRIV_KEY" "$LOCAL_DIR" "$SERVER:$BASE_DIR/"

ssh -i "$SSH_PRIV_KEY" "$SERVER" bash -s -- "$BASE_DIR" <<'REMOTE'
  cd "$1"
  PEW_CMD=$(command -v pew || echo "/root/.local/bin/pew")
  "$PEW_CMD" in zardaxt pip install -r requirements.txt --quiet
  /bin/bash restart.sh
  sleep 4
  KEY=$(python3 -c 'import json; print(json.load(open("zardaxt-server.json"))["api_key"])')
  curl -sf "http://127.0.0.1:8249/stats?key=$KEY" && echo && tail -3 log/zardaxt.log
REMOTE
echo "Deployed zardaxt to $SERVER"
