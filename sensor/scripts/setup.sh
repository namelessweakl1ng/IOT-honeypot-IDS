#!/usr/bin/env sh
set -eu
fail() { echo "ERROR: $*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail "Docker is required"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
[ -f .env ] || fail "missing sensor/.env (run: cp .env.example .env, then edit it)"
set -a
# shellcheck disable=SC1091
. ./.env
set +a
[ -n "${ANALYSIS_HOST:-}" ] || fail "ANALYSIS_HOST must be set"
[ -n "${SENSOR_IP:-}" ] || fail "SENSOR_IP must be set"
[ -n "${SENSOR_ID:-}" ] || fail "SENSOR_ID must be set"
docker compose config >/dev/null || fail "docker compose config failed"
echo "Architecture: $(uname -m)"
if id trapsig >/dev/null 2>&1; then
  if ! id -nG trapsig | tr ' ' '\n' | grep -qx docker; then
    fail "user 'trapsig' is not in the docker group; run: sudo usermod -aG docker trapsig (then start a new login/SSH session)"
  fi
else
  echo "WARNING: management user 'trapsig' does not exist yet; create it and add it to the docker group before backend management is used." >&2
fi
if ! docker info --format '{{json .Warnings}}' 2>/dev/null | grep -qv 'No memory limit support'; then
  echo "WARNING: Docker reports that memory limits may not be enforced." >&2
fi
echo 'TRAPSIG sensor preflight passed.'
