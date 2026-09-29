#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
if [ -z "${TRAPSIG_REVISION:-}" ] && command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  TRAPSIG_REVISION=$(git rev-parse HEAD)
  export TRAPSIG_REVISION
fi
docker compose up -d
