#!/usr/bin/env bash
# One-time project setup — call this after `git clone`.
set -euo pipefail

cd "$(dirname "$0")/../.."
echo "=== Project setup ==="

# 1. Root .env
if [ ! -f .env ]; then
  cp .env.example .env
  echo "  created .env (edit it before deploying)"
fi

# 2. Per-module .env files
for f in pi/.env dashboard/.env attacker/.env; do
  if [ ! -f "$f" ]; then
    cp "${f}.example" "$f"
    echo "  created $f"
  fi
done

# 3. Python venv for model-lab + tests
if [ ! -d .venv ]; then
  python3 -m venv .venv
  echo "  created .venv"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r dashboard/api/requirements.txt
pip install --quiet pytest
echo "  python deps installed"

# Setup does not generate or select research data. Use an identified external
# dataset or independently recorded controlled-campaign labels.

echo
echo "=== Setup complete ==="
echo "Next:"
echo "  - Edit .env files (root, pi/, dashboard/, attacker/)"
echo "  - No dataset was generated; synthetic fixtures are development-only."
echo "  - PC1: cd dashboard && docker compose up -d"
echo "  - Pi:  ssh to Pi, cd pi/ && ./scripts/configure.sh && ./scripts/start.sh"
echo "  - PC2: cd attacker && ./run-scenario.sh --target <PI_IP> --scenario ssh-bruteforce"
