#!/usr/bin/env bash
# Start ELK + API on PC1.
set -euo pipefail
cd "$(dirname "$0")/../../dashboard"
[ -f .env ] || { echo "ERROR: dashboard/.env missing. Run scripts/setup/init.sh first." >&2; exit 1; }
set -a; source .env; set +a
echo "=== Starting ELK + API on PC1 ==="
docker compose up -d
echo "Allowing containers 15s to begin initialization..."
sleep 15
docker compose ps
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
echo "=== Bootstrapping Elasticsearch templates + ILM ==="
bash "${REPO_ROOT}/scripts/deployment/bootstrap-elasticsearch.sh" \
  || { echo "ERROR: ES bootstrap failed — indices will not have correct mappings" >&2; exit 1; }
echo "Kibana: http://localhost:5601"
echo "API:    http://localhost:8000/health"
