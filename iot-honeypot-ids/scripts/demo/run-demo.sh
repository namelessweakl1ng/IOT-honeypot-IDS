#!/usr/bin/env bash
# =====================================================================
# Final-year-project demo runner.
# Walks through: system check -> honeypot check -> ELK check -> attack
# -> telemetry -> session reconstruction -> ML detection -> unknown
# pattern -> label -> retrain -> evaluate -> replay -> final detection.
#
# Usage:
#   ./scripts/demo/run-demo.sh --target 192.168.1.50
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")/../.."

TARGET=""
SCENARIO_KNOWN="${SCENARIO_KNOWN:-ssh-bruteforce}"
SCENARIO_UNKNOWN="${SCENARIO_UNKNOWN:-http-enumeration}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --known)  SCENARIO_KNOWN="$2"; shift 2 ;;
    --unknown) SCENARIO_UNKNOWN="$2"; shift 2 ;;
    -h|--help) echo "Usage: $0 --target <ip> [--known ssh-bruteforce] [--unknown http-enumeration]"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$TARGET" ] || { echo "ERROR: --target is required" >&2; exit 2; }

step() { echo; echo "========== $* =========="; }

step "STAGE 1: SYSTEM CHECK"
if [ -d .venv ]; then source .venv/bin/activate; fi
echo "PC1 health:"
curl -sf http://localhost:8000/health | python3 -m json.tool || { echo "FAIL: API not reachable"; exit 1; }

step "STAGE 2: HONEYPOT CHECK"
echo "Probing camera honeypot at http://${TARGET}:8080/"
curl -sf -o /dev/null -w "camera /health -> %{http_code}\n" "http://${TARGET}:8080/health" || \
  { echo "FAIL: camera honeypot not reachable"; exit 1; }

step "STAGE 3: ELK CHECK"
curl -sf -u "elastic:${ELASTIC_PASSWORD:-changeme-elastic}" \
  "http://localhost:9200/_cluster/health" | python3 -m json.tool | head -5 || \
  { echo "FAIL: Elasticsearch not reachable"; exit 1; }

step "STAGE 4: ATTACK (known pattern: ${SCENARIO_KNOWN})"
./attacker/run-scenario.sh --target "$TARGET" --scenario "$SCENARIO_KNOWN" --campaign-id "demo-known"

step "STAGE 5: WAIT FOR TELEMETRY"
echo "sleeping 5s..."
sleep 5

step "STAGE 6: SESSION RECONSTRUCTION"
curl -sf "http://localhost:8000/sessions?size=3" | python3 -m json.tool | head -30

step "STAGE 7: ML DETECTION (known pattern)"
MODEL_ID="${MODEL_ID:-model-v001}"
if [ ! -d "model-lab/models/${MODEL_ID}" ]; then
  echo "No model found at model-lab/models/${MODEL_ID} — training one from synthetic data..."
  mkdir -p model-lab/datasets/v1
  [ -f model-lab/datasets/v1/sessions.csv ] || \
    python -m model_lab.datasets.bootstrap --out model-lab/datasets/v1/sessions.csv
  python -m model_lab.train --algorithm random_forest --seed 42 --model-id "$MODEL_ID"
fi
echo "Model: ${MODEL_ID}"

step "STAGE 8: UNKNOWN PATTERN"
./attacker/run-scenario.sh --target "$TARGET" --scenario "$SCENARIO_UNKNOWN" --campaign-id "demo-unknown"

step "STAGE 9: WAIT FOR TELEMETRY"
echo "sleeping 5s..."
sleep 5

step "STAGE 10: RETRAIN (with the new session as a new label)"
python -m model_lab.train --algorithm random_forest --seed 42 --model-id "model-v002" || \
  echo "(retrain skipped — see above)"

step "STAGE 11: EVALUATE NEW MODEL"
python -m model_lab.evaluate --model-id "model-v002" || \
  echo "(evaluate skipped — see above)"

step "STAGE 12: REPLAY UNKNOWN PATTERN WITH NEW MODEL"
python -m model_lab.replay --scenario "$SCENARIO_UNKNOWN" --target "$TARGET" --model-id "model-v002" || \
  echo "(replay skipped — see above)"

step "FINAL DETECTION"
echo "Demo complete. Inspect model-lab/experiments/ for the recorded metrics."
echo "Open Kibana at http://localhost:5601 to view the dashboards."
