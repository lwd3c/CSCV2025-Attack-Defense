#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

KEY=$(openssl rand -hex 32)
echo "[*] Container: $(basename $SCRIPT_DIR)"
echo "[*] Generated KEY: $KEY"

cat > .env << EOF
KEY=$KEY
EOF

echo "[*] .env file created at: $SCRIPT_DIR/.env"

sudo docker compose up -build -d