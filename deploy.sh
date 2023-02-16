#!/bin/bash

# add your env variables into a file .env
source .env

# sync webapp
rsync --chown www-data:www-data --exclude-from "$LOCAL_DIR/exclude.txt" \
 -Pav -e "ssh -i $SSH_PRIV_KEY" $LOCAL_DIR $SERVER:$BASE_DIR

ssh -i $SSH_PRIV_KEY $SERVER << EOF
  cd /root/zardaxt/;
  ./restart.sh
EOF

echo "Deployed zardaxt.py"
