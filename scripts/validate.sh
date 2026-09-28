#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
docker compose config >/dev/null
docker compose -f sensor/docker-compose.yml --env-file sensor/.env.example config >/dev/null
python -m pytest
(cd frontend && npm run lint && npm run build)
echo 'TRAPSIG validation passed.'
