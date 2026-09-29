#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
docker compose config >/dev/null
docker compose -f sensor/docker-compose.yml --env-file sensor/.env.example config >/dev/null
./scripts/ci/check-shell.sh
./scripts/test.sh
(cd frontend && npm run build)
echo 'TRAPSIG validation passed.'
