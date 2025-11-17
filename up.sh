#!/bin/bash

# Generate random MASTER_KEY (16 characters)
MASTER_KEY=$(openssl rand -hex 8)
echo "[*] Generated MASTER_KEY: $MASTER_KEY"

# Update .env file with new MASTER_KEY
cat > .env << EOF
MASTER_KEY=$MASTER_KEY
EOF


echo "[*] Stopping any existing container..."
docker-compose down

echo "[*] Starting container..."
docker-compose up -d file_manager

echo "[*] Waiting for service to be ready..."
sleep 2

# Check if container is running
if docker-compose ps | grep -q "Up"; then
    echo "[✓] Container started successfully!"
    echo "[✓] File manager is accessible at: nc localhost 7331"
    echo ""
    echo "Useful commands:"
    echo "  - View logs:    docker-compose logs -f"
    echo "  - Stop service: docker-compose down"
    echo ""
    echo "Good luck and have fun!"
else
    echo "[!] Error: Container failed to start"
    echo "[!] Check logs with: docker-compose logs"
    exit 1
fi
