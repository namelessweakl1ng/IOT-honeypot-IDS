#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
python -m pytest
(cd frontend && npm run lint)
