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
if ! docker info --format '{{json .Warnings}}' 2>/dev/null | grep -qv 'No memory limit support'; then
  echo "WARNING: Docker reports that memory limits may not be enforced." >&2
fi
echo 'TRAPSIG sensor preflight passed.'
