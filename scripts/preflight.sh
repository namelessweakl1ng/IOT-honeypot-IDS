#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."

fail() { echo "ERROR: $*" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || fail "Docker is not installed or not on PATH"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
[ -f .env ] || fail "missing .env (run: cp .env.example .env)"

set -a
# shellcheck disable=SC1091
. ./.env
set +a
if [ -n "${PI_HOST:-}" ]; then
  key=${PI_SSH_KEY_PATH:-./secrets/pi_ssh_key}
  hosts=${PI_KNOWN_HOSTS_PATH:-./secrets/known_hosts}
  [ -s "$key" ] || fail "PI_HOST is set but private key is missing or empty: $key"
  [ -s "$hosts" ] || fail "PI_HOST is set but known_hosts is missing or empty: $hosts"
fi
docker compose config >/dev/null || fail "docker compose config failed"
if [ -r /etc/fedora-release ] && command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = Enforcing ]; then
  echo "INFO: SELinux is Enforcing; repository bind mounts use private :Z relabeling."
fi
echo "TRAPSIG analysis preflight passed."
