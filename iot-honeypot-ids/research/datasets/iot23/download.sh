#!/usr/bin/env bash
# Explicit opt-in download; delegates external-path and checksum checks.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
[[ -n "${IOT23_DATA_DIR:-}" ]] || { echo "Set IOT23_DATA_DIR to a directory outside the repository." >&2; exit 2; }
exec "$ROOT/scripts/research/prepare-iot23.sh" --download "$@"
