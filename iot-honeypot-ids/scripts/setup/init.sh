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

# 4. Create the synthetic dataset if missing
mkdir -p model-lab/datasets/v1
if [ ! -f model-lab/datasets/v1/sessions.csv ]; then
  python -m model_lab.datasets.bootstrap --out model-lab/datasets/v1/sessions.csv
fi

echo
echo "=== Setup complete ==="
echo "Next:"
echo "  - Edit .env files (root, pi/, dashboard/, attacker/)"
echo "  - PC1: cd dashboard && docker compose up -d"
echo "  - Pi:  ssh to Pi, cd pi/ && ./scripts/configure.sh && ./scripts/start.sh"
echo "  - PC2: cd attacker && ./run-scenario.sh --target <PI_IP> --scenario ssh-bruteforce"
