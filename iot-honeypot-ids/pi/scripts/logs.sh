#!/usr/bin/env bash
# Tail logs from one or all honeypot services.
# Usage: ./scripts/logs.sh [service]
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$#" -ge 1 ]; then
  echo ">> docker compose logs -f --tail=200 $1"
  exec docker compose logs -f --tail=200 "$1"
else
  echo ">> docker compose logs -f --tail=200"
  exec docker compose logs -f --tail=200
fi
