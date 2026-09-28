#!/usr/bin/env sh
set -eu
command -v docker >/dev/null || { echo 'Docker is required' >&2; exit 1; }
[ -f .env ] || cp .env.example .env
docker compose config >/dev/null
echo 'TRAPSIG sensor configuration is ready.'
