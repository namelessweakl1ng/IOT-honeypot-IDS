#!/usr/bin/env bash
# Sanity-check the Pi environment and .env before first start.
set -euo pipefail
cd "$(dirname "$0")/.."

ok=true
err() { echo "ERROR: $*" >&2; ok=false; }
warn() { echo "WARN: $*"; }

echo "== Pi honeypot configure =="

# 1. .env present?
[ -f .env ] || { echo "Copying .env.example -> .env"; cp .env.example .env; warn "edit .env and set CENTRAL_SERVER_IP"; }

# shellcheck disable=SC1091
set -a; source .env; set +a

# 2. Docker + Compose available?
command -v docker >/dev/null 2>&1 || err "docker not installed"
docker compose version >/dev/null 2>&1 || err "docker compose plugin not available"

# 3. Required vars set?
[ -n "${CENTRAL_SERVER_IP:-}" ] || err "CENTRAL_SERVER_IP not set"
[[ "${CENTRAL_SERVER_IP}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
  err "CENTRAL_SERVER_IP does not look like an IPv4: $CENTRAL_SERVER_IP"

# 4. Optional vars sanity
[ -n "${COWRIE_SSH_PORT:-}" ] || warn "COWRIE_SSH_PORT not set, default 2222 will be used"
[ -n "${CAMERA_HTTP_PORT:-}" ] || warn "CAMERA_HTTP_PORT not set, default 8080 will be used"
[ -n "${IOT_SERVICE_PORT:-}" ] || warn "IOT_SERVICE_PORT not set, default 9000 will be used"

# 5. Host ports free?
for port in "${COWRIE_SSH_PORT:-2222}" "${COWRIE_TELNET_PORT:-2223}" "${CAMERA_HTTP_PORT:-8080}" "${IOT_SERVICE_PORT:-9000}"; do
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$port$"; then
    warn "host port $port already in use — adjust in .env"
  fi
done

# 6. PC1 reachable on the Beats port?
if command -v nc >/dev/null 2>&1; then
  if nc -z -w 3 "${CENTRAL_SERVER_IP}" "${LOGSTASH_BEATS_PORT:-5044}" 2>/dev/null; then
    echo "OK: PC1 Logstash reachable on ${CENTRAL_SERVER_IP}:${LOGSTASH_BEATS_PORT:-5044}"
  else
    warn "PC1 Logstash not reachable yet — Filebeat will retry"
  fi
fi

# 7. Disk space?
free_mb=$(df -m . | awk 'NR==2 {print $4}')
[ "$free_mb" -gt 512 ] || warn "low disk space on Pi: ${free_mb} MB free"

if $ok; then
  echo "OK: configuration looks good. Run ./scripts/start.sh to start the fleet."
else
  echo "ERRORS found — fix the issues above and re-run ./scripts/configure.sh"
  exit 1
fi
