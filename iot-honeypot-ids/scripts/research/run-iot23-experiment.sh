#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PYTHONPATH="$ROOT/model-lab${PYTHONPATH:+:$PYTHONPATH}" python3 "$ROOT/scripts/research/run_iot23_experiment.py" "$@"
