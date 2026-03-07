#!/bin/bash

BASE_DIR=/root/zardaxt
SERVER_US=root@5.161.181.126
SSH_PRIV_KEY=/Users/nikolaitschacher/.ssh/pd_server
SERVER_DE=root@168.119.226.219

PD_DIR=/var/www/proxyDetector
NODE_US=/root/.nvm/versions/node/v22.21.1/bin/node
NODE_DE=/root/.nvm/versions/node/v18.20.4/bin/node
REMOTE_FILE=/tmp/tcp_ip_fingerprints.json
LOCAL_DIR=/Users/nikolaitschacher/projects/zardaxt/database/rawData

echo "=== Exporting TCP/IP fingerprints on US server ==="
ssh -i $SSH_PRIV_KEY $SERVER_US "cd $PD_DIR && $NODE_US pdAnalyze.js tcpip"
echo "=== Downloading from US server ==="
scp -i $SSH_PRIV_KEY $SERVER_US:$REMOTE_FILE $LOCAL_DIR/tcp_ip_fingerprints-us.json

echo "=== Exporting TCP/IP fingerprints on DE server ==="
ssh -i $SSH_PRIV_KEY $SERVER_DE "cd $PD_DIR && $NODE_DE pdAnalyze.js tcpip"
echo "=== Downloading from DE server ==="
scp -i $SSH_PRIV_KEY $SERVER_DE:$REMOTE_FILE $LOCAL_DIR/tcp_ip_fingerprints-de.json

echo "=== Downloads complete ==="
ls -lh $LOCAL_DIR/tcp_ip_fingerprints-*.json

echo "=== Preparing TCP/IP fingerprint database ==="
cd /Users/nikolaitschacher/projects/zardaxt/database
node prepare.js ./rawData/tcp_ip_fingerprints-de.json ./rawData/tcp_ip_fingerprints-us.json

echo "=== Done ==="
