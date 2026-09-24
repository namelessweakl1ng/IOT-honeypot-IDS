#!/usr/bin/env bash
# Stop ELK + API on PC1.
set -euo pipefail
cd "$(dirname "$0")/../../dashboard"
docker compose down
echo "PC1 stack stopped."
