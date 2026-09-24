#!/usr/bin/env bash
# =====================================================================
# Attacker scenario runner — the single entry point for all scenarios.
#
# Usage:
#   ./run-scenario.sh --target <ip> --scenario <id> [--campaign-id <id>]
#
# Safety:
#   * --target is REQUIRED (no default)
#   * target must be inside LAB_SUBNET
#   * target must not be a loopback/link-local/multicast/public-routed IP
#   * scenarios are scoped to the configured honeypot ports
# =====================================================================
set -euo pipefail

cd "$(dirname "$0")"

# ------------------------------------------------------------------
# Load env
# ------------------------------------------------------------------
if [ -f .env ]; then
  set -a; source .env; set +a
else
  echo "ERROR: .env not found. Copy .env.example -> .env and edit." >&2
  exit 2
fi

# ------------------------------------------------------------------
# Args
# ------------------------------------------------------------------
TARGET=""
SCENARIO=""
CAMPAIGN_ID=""
DELAY="${DEFAULT_DELAY:-0.2}"

usage() {
  cat <<USAGE
Usage: $0 --target <ip> --scenario <id> [--campaign-id <id>] [--delay <s>]

Required:
  --target <ip>      IP of the lab honeypot (must be inside LAB_SUBNET)
  --scenario <id>    One of the ids in scenarios/*.yaml

Optional:
  --campaign-id <id> Custom campaign id (otherwise auto-generated)
  --delay <s>        Delay between probes in seconds (default $DEFAULT_DELAY)
USAGE
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)        TARGET="$2"; shift 2 ;;
    --scenario)     SCENARIO="$2"; shift 2 ;;
    --campaign-id)  CAMPAIGN_ID="$2"; shift 2 ;;
    --delay)        DELAY="$2"; shift 2 ;;
    -h|--help)      usage ;;
    *) echo "ERROR: unknown arg: $1" >&2; usage ;;
  esac
done

[ -n "$TARGET" ]    || { echo "ERROR: --target is required" >&2; usage; }
[ -n "$SCENARIO" ]  || { echo "ERROR: --scenario is required" >&2; usage; }

# ------------------------------------------------------------------
# Safety check: target must be inside LAB_SUBNET
# ------------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 required for safety check" >&2
  exit 3
fi

python3 - <<PY || exit 4
import os, sys, ipaddress
target = os.environ.get("TARGET", "")
subnet = os.environ.get("LAB_SUBNET", "")
try:
    ip = ipaddress.ip_address(target)
except ValueError:
    print(f"ERROR: target {target!r} is not a valid IP", file=sys.stderr)
    sys.exit(1)

# Refuse loopback, link-local, multicast, unspecified
if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
    print(f"ERROR: target {target} is loopback/link-local/multicast/unspecified", file=sys.stderr)
    sys.exit(1)

if not subnet:
    print("ERROR: LAB_SUBNET not set in .env", file=sys.stderr)
    sys.exit(1)

try:
    net = ipaddress.ip_network(subnet, strict=False)
except ValueError as e:
    print(f"ERROR: bad LAB_SUBNET {subnet!r}: {e}", file=sys.stderr)
    sys.exit(1)

if ip not in net:
    print(f"ERROR: target {target} not in lab subnet {subnet}", file=sys.stderr)
    print("       refusing to run scenario against non-lab IP.", file=sys.stderr)
    sys.exit(1)

print(f"OK: target {target} in lab subnet {subnet}")
PY

# ------------------------------------------------------------------
# Scenario file lookup
# ------------------------------------------------------------------
SCENARIO_FILE="scenarios/${SCENARIO}.yaml"
if [ ! -f "$SCENARIO_FILE" ]; then
  echo "ERROR: scenario file not found: $SCENARIO_FILE" >&2
  echo "Available scenarios:" >&2
  ls scenarios/ 2>/dev/null | sed 's/^/  - /' >&2
  exit 5
fi

# ------------------------------------------------------------------
# Generate campaign_id / run_id
# ------------------------------------------------------------------
if [ -z "$CAMPAIGN_ID" ]; then
  CAMPAIGN_ID="campaign-$(date -u +%Y%m%dT%H%M%SZ)-$(printf '%06x' $((RANDOM % 16777215)))"
fi
RUN_ID="run-$(date -u +%Y%m%dT%H%M%SZ)-$(printf '%06x' $((RANDOM % 16777215)))"
export TARGET SCENARIO CAMPAIGN_ID RUN_ID

echo "==============================================================="
echo " Campaign: $CAMPAIGN_ID"
echo " Run:      $RUN_ID"
echo " Scenario: $SCENARIO"
echo " Target:   $TARGET (in $LAB_SUBNET)"
echo " Delay:    ${DELAY}s"
echo "==============================================================="

# Source the runner library
source runner/lib.sh

# Dispatch
case "$SCENARIO" in
  ssh-bruteforce)         runner_ssh_bruteforce ;;
  ssh-interaction)        runner_ssh_interaction ;;
  camera-recon)           runner_camera_recon ;;
  camera-default-creds)   runner_camera_default_creds ;;
  http-enumeration)       runner_http_enumeration ;;
  iot-probe)              runner_iot_probe ;;
  multi-stage)            runner_multi_stage ;;
  *)
    echo "ERROR: scenario '$SCENARIO' has no runner implementation." >&2
    exit 6
    ;;
esac

# Write run summary
mkdir -p "${RUNS_DIR:-./runs}"
SUMMARY="${RUNS_DIR:-./runs}/${RUN_ID}.json"
python3 - <<PY > "$SUMMARY"
import json, os, datetime
print(json.dumps({
    "campaign_id": os.environ["CAMPAIGN_ID"],
    "run_id":      os.environ["RUN_ID"],
    "scenario":    os.environ["SCENARIO"],
    "target":      os.environ["TARGET"],
    "lab_subnet":  os.environ["LAB_SUBNET"],
    "started_at":  os.environ.get("RUN_STARTED_ISO", ""),
    "ended_at":    datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
}, indent=2))
PY

echo
echo "Run summary written to $SUMMARY"
