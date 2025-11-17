#!/bin/bash

echo "[*] Container: $(basename $(pwd))"
echo "[*] Generated KEY: $KEY"

TOKEN=$(echo -n "admin:${KEY}" | sha1sum | awk '{print $1}')
echo "$TOKEN" > /tmp/storage/admin/token.txt
chmod 440 /tmp/storage/admin/*

socat TCP-LISTEN:3636,reuseaddr,fork EXEC:/home/icon/chall