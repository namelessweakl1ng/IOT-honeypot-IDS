#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
python -m ruff check backend attacks evaluation tests
python -m pytest -q
(cd frontend && npm run lint && npm run typecheck)
