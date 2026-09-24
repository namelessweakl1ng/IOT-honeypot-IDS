#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/stop.sh
./scripts/start.sh
