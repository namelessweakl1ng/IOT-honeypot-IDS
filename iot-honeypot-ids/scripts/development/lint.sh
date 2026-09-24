#!/usr/bin/env bash
# Run linters + type checks across the project.
set -euo pipefail
cd "$(dirname "$0")/../.."

if [ -d .venv ]; then source .venv/bin/activate; fi

echo "=== Python lint ==="
pip install --quiet ruff mypy 2>/dev/null || true
ruff check dashboard/api/app dashboard/ml model-lab/model_lab shared 2>&1 || echo "(ruff found issues — non-fatal)"

echo "=== Python type check (best-effort) ==="
mypy dashboard/api/app --ignore-missing-imports 2>&1 || echo "(mypy found issues — non-fatal)"

echo "=== Frontend type check ==="
echo "  (authoritative frontend is the workspace-root Next.js app; run 'bun run lint' and 'bun run build' there)"

echo "=== Done ==="
