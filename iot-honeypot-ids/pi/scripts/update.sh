#!/usr/bin/env bash
# Pull latest code + rebuild honeypot images + restart.
set -euo pipefail
cd "$(dirname "$0")/.."
echo ">> git pull"
git pull --ff-only
echo ">> docker compose build"
docker compose build --pull
./scripts/restart.sh
echo ">> update complete."
