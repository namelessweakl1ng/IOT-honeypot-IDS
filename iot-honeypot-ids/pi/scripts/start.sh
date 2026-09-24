#!/usr/bin/env bash
# Start the Pi honeypot fleet (Docker Compose)
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f .env ] || { echo "ERROR: .env not found. Run ./scripts/configure.sh first." >&2; exit 1; }

# Pull only honeypot profiles that are enabled in .env
PROFILES=()
grep -qE '^ENABLE_COWRIE=true'        .env && PROFILES+=(cowrie)
grep -qE '^ENABLE_CAMERA=true'        .env && PROFILES+=(camera)
grep -qE '^ENABLE_IOT_SERVICE=true'  .env && PROFILES+=(iot-service)
PROFILES+=(default)   # filebeat always runs

PROFILE_ARG=""
for p in "${PROFILES[@]}"; do PROFILE_ARG+=" --profile $p"; done

echo ">> docker compose up -d$PROFILE_ARG"
# shellcheck disable=SC2086
docker compose $PROFILE_ARG up -d
echo ">> fleet started. Run ./scripts/status.sh to verify."
