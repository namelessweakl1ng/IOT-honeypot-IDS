#!/usr/bin/env bash
# Run unit + integration tests.
set -euo pipefail
cd "$(dirname "$0")/../.."

if [ -d .venv ]; then source .venv/bin/activate; fi

echo "=== Unit tests ==="
pytest tests/unit -v

echo
echo "=== Integration tests ==="
pytest tests/integration -v --tb=short
