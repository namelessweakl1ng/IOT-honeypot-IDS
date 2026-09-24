#!/usr/bin/env bash
# Stop the Pi honeypot fleet (keeps volumes so logs are not lost)
set -euo pipefail
cd "$(dirname "$0")/.."
echo ">> docker compose down"
docker compose down
echo ">> fleet stopped."
