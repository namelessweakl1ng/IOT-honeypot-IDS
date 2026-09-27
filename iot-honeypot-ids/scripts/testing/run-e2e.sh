#!/usr/bin/env bash
# End-to-end test: attack scenario -> telemetry -> session -> detection.
# Usage: ./scripts/testing/run-e2e.sh --target 192.168.1.50 --scenario camera-recon
set -euo pipefail
cd "$(dirname "$0")/../.."

TARGET=""
SCENARIO="${SCENARIO:-ssh-bruteforce}"
CAMPAIGN_ID=""
RUN_ID=""
TEST_START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --scenario) SCENARIO="$2"; shift 2 ;;
    --campaign-id) CAMPAIGN_ID="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$TARGET" ] || { echo "ERROR: --target is required" >&2; exit 2; }

if [ -z "$CAMPAIGN_ID" ]; then
  CAMPAIGN_ID="campaign-$(date -u +%Y%m%dT%H%M%SZ)-$(printf '%06x' $((RANDOM % 16777215)))"
fi
API_URL="${API_URL:-http://localhost:8000}"
API_KEY="${API_SECRET_KEY:-}"
[ -n "$API_KEY" ] || { echo "ERROR: API_SECRET_KEY is required for LIVE detection" >&2; exit 2; }
export TEST_START_ISO API_URL API_KEY SCENARIO

case "$SCENARIO" in
  ssh-*) EXPECTED_HONEYPOT="cowrie" ;;
  camera-*) EXPECTED_HONEYPOT="camera" ;;
  iot-*) EXPECTED_HONEYPOT="iot-service" ;;
  *) EXPECTED_HONEYPOT="" ;;
esac
export EXPECTED_HONEYPOT

echo "=== E2E: $SCENARIO against $TARGET (expect honeypot: auto-detected) ==="
echo "attacker_campaign_tag: $CAMPAIGN_ID"
echo "test_start:  $TEST_START_ISO"

echo ">> launching attacker scenario"
command -v timeout >/dev/null 2>&1 || { echo "ERROR: timeout is required to bound the attacker run" >&2; exit 2; }
if ! ATTACK_OUTPUT="$(timeout "${ATTACK_TIMEOUT_SECONDS:-180}" ./attacker/run-scenario.sh --target "$TARGET" --scenario "$SCENARIO" --campaign-id "$CAMPAIGN_ID" 2>&1)"; then
  printf '%s\n' "$ATTACK_OUTPUT" >&2
  echo "FAIL: attacker scenario failed or exceeded ${ATTACK_TIMEOUT_SECONDS:-180}s" >&2
  exit 1
fi
printf '%s\n' "$ATTACK_OUTPUT"
RUN_ID="$(printf '%s\n' "$ATTACK_OUTPUT" | sed -n 's/^[[:space:]]*Run:[[:space:]]*//p' | tail -n 1)"
if [ -z "$RUN_ID" ]; then echo "FAIL: attacker output did not include its run_id" >&2; exit 1; fi

echo ">> polling FastAPI/Elasticsearch for the new event (timeout 60s, every 2s)"
NEW_EVENT_DOC=""
elapsed=0
while [ "$elapsed" -lt 60 ]; do
  NEW_EVENT_DOC="$(python3 - <<'PY' || true
import datetime, json, os, urllib.request
url = os.environ.get("API_URL", "http://localhost:8000") + "/events?size=200"
try:
    with urllib.request.urlopen(url, timeout=10) as response:
        rows = json.loads(response.read()).get("events", [])
    # This is the API-side equivalent of an Elasticsearch @timestamp gte filter.
    gte = datetime.datetime.fromisoformat(os.environ["TEST_START_ISO"].replace("Z", "+00:00"))
    expected = os.environ.get("EXPECTED_HONEYPOT", "")
    candidates = []
    for event in rows:
        stamp = event.get("@timestamp")
        try:
            parsed = datetime.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if parsed >= gte and (not expected or (event.get("honeypot") or {}).get("name") == expected):
            candidates.append(event)
    if candidates:
        candidates.sort(key=lambda row: row.get("@timestamp", ""), reverse=True)
        print(json.dumps(candidates[0]))
except Exception:
    pass
PY
)"
  if [ -n "$NEW_EVENT_DOC" ]; then
    echo ">> found new event through FastAPI"
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
if [ -z "$NEW_EVENT_DOC" ]; then
  echo "FAIL: no new event appeared in ES within 60s" >&2
  exit 1
fi

echo "$NEW_EVENT_DOC" | python3 -c "
import sys, json
doc = json.load(sys.stdin)
required = ['event_id', 'session_id', '@timestamp', 'source', 'device', 'honeypot', 'event', 'ingested_at', 'timestamp_source']
missing = []
for f in required:
    cur = doc; ok = True
    for p in f.split('.'):
        if not isinstance(cur, dict) or p not in cur:
            ok = False; break
        cur = cur[p]
    if not ok: missing.append(f)
if missing:
    print('FAIL: event missing required fields: ' + ', '.join(missing), file=sys.stderr)
    sys.exit(1)
leaves = {
    'event_id':     doc.get('event_id', ''),
    'session_id':   doc.get('session_id', ''),
    '@timestamp':   doc.get('@timestamp', ''),
    'source.ip':    doc.get('source', {}).get('ip', ''),
    'device.id':    doc.get('device', {}).get('id', ''),
    'honeypot.name': doc.get('honeypot', {}).get('name', ''),
    'event.type':   doc.get('event', {}).get('type', ''),
    'ingested_at':  doc.get('ingested_at', ''),
    'timestamp_source': doc.get('timestamp_source', ''),
}
empty_leaves = [k for k, v in leaves.items() if not v]
if empty_leaves:
    print('FAIL: event has empty leaf fields: ' + ', '.join(empty_leaves), file=sys.stderr)
    sys.exit(1)
print('OK: event has all required leaf fields')
"

SESSION_ID="$(echo "$NEW_EVENT_DOC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))")"
EVENT_ID="$(echo "$NEW_EVENT_DOC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id',''))")"
SOURCE_IP="$(echo "$NEW_EVENT_DOC" | python3 -c "import sys,json; print((json.load(sys.stdin).get('source') or {}).get('ip',''))")"
export API_URL EVENT_ID SESSION_ID SOURCE_IP
if [ -z "$SESSION_ID" ] || [ -z "$EVENT_ID" ]; then
  echo "FAIL: extracted session_id or event_id is empty" >&2; exit 1
fi

echo ">> verifying FastAPI /events returns this event"
python3 - <<PY
import os, sys, json, urllib.request
api_url = os.environ.get("API_URL", "http://localhost:8000")
try:
    r = urllib.request.urlopen(f"{api_url}/events?size=50", timeout=10)
    j = json.loads(r.read())
    target_id = os.environ.get("EVENT_ID")
    for e in j.get("events", []):
        if e.get("event_id") == target_id:
            print("OK: event found via /events")
            sys.exit(0)
    print(json.dumps({"found": False}))
    sys.exit(1)
except Exception as e:
    print(f"FAIL: /events unreachable: {e}", file=sys.stderr)
    sys.exit(1)
PY

echo ">> polling FastAPI /sessions for the new session (timeout 90s, every 3s)"
SESSION_FOUND=0
elapsed=0
while [ "$elapsed" -lt 90 ]; do
  result="$(python3 - <<PY
import os, sys, json, urllib.request
api_url = os.environ.get("API_URL", "http://localhost:8000")
target_sid = os.environ.get("SESSION_ID", "")
try:
    r = urllib.request.urlopen(f"{api_url}/sessions?size=100", timeout=10)
    j = json.loads(r.read())
    for s in j.get("sessions", []):
        if s.get("session_id") == target_sid:
            print(json.dumps({"found": True, "session": s}))
            sys.exit(0)
    print(json.dumps({"found": False}))
except Exception as e:
    print(json.dumps({"found": False, "error": str(e)}))
PY
)"
  if echo "$result" | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin).get('found') else 1)"; then
    SESSION_FOUND=1
    echo ">> session materialized"
    break
  fi
  sleep 3
  elapsed=$((elapsed + 3))
done
if [ "$SESSION_FOUND" -ne 1 ]; then
  echo "FAIL: session $SESSION_ID not materialized within 90s" >&2
  exit 1
fi

echo ">> verifying GET /sessions/{id} returns timeline with our event_id"
python3 - <<PY
import os, sys, json, urllib.request
api_url = os.environ.get("API_URL", "http://localhost:8000")
sid = os.environ.get("SESSION_ID")
target_eid = os.environ.get("EVENT_ID")
try:
    r = urllib.request.urlopen(f"{api_url}/sessions/{sid}", timeout=10)
    j = json.loads(r.read())
    events = j.get("events", [])
    event_ids = [e.get("event_id") for e in events if isinstance(e, dict)]
    print(json.dumps({"session_id": j.get("session_id"), "event_count": len(events),
                      "event_ids": event_ids[:20], "target_present": target_eid in event_ids}))
    if not target_eid in event_ids:
        sys.exit(1)
    print("OK: /sessions/{id} returns timeline with our event")
except Exception as e:
    print(f"FAIL: {e}", file=sys.stderr)
    sys.exit(1)
PY

echo ">> verifying runtime features are extracted from this session"
python3 - <<'PY'
import json, os, sys, urllib.request
base = os.environ.get("API_URL", "http://localhost:8000")
sid = os.environ["SESSION_ID"]
try:
    req = urllib.request.Request(f"{base}/features/{sid}")
    with urllib.request.urlopen(req, timeout=15) as response:
        features = json.loads(response.read())
    if features.get("session_id") != sid or not features.get("feature_schema_version") or not isinstance(features.get("features"), dict):
        raise RuntimeError("feature response does not identify the session and versioned feature object")
    print(json.dumps({"session_id": sid, "feature_schema_version": features["feature_schema_version"],
                      "feature_count": len(features["features"]), "source": features.get("source")}))
except Exception as exc:
    print(f"FAIL: feature extraction verification: {exc}", file=sys.stderr)
    sys.exit(1)
PY

echo ">> correlating and verifying the backend campaign contains this session"
python3 - <<'PY'
import json, os, sys, urllib.parse, urllib.request
base = os.environ.get("API_URL", "http://localhost:8000")
sid = os.environ["SESSION_ID"]
source_ip = os.environ.get("SOURCE_IP", "")
headers = {"X-API-Key": os.environ["API_KEY"]}
try:
    req = urllib.request.Request(f"{base}/campaigns/correlate?lookback_minutes=240", headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as response:
        correlation = json.loads(response.read())
    query = urllib.parse.urlencode({"source_ip": source_ip, "size": 100})
    with urllib.request.urlopen(f"{base}/campaigns?{query}", timeout=15) as response:
        campaigns = json.loads(response.read()).get("campaigns", [])
    campaign = next((item for item in campaigns if sid in (item.get("session_ids") or [])), None)
    if not campaign or not campaign.get("campaign_id"):
        raise RuntimeError("campaign correlator did not link the observed session; inspect its status and source-IP/time grouping")
    os.environ["BACKEND_CAMPAIGN_ID"] = campaign["campaign_id"]
    print(json.dumps({"campaign_id": campaign["campaign_id"], "session_id": sid,
                      "session_ids": campaign.get("session_ids"), "source_ip": source_ip,
                      "correlation_result": correlation}))
except Exception as exc:
    print(f"FAIL: campaign lineage verification: {exc}", file=sys.stderr)
    sys.exit(1)
PY

BACKEND_CAMPAIGN_ID="$(python3 -c 'import json,os,urllib.parse,urllib.request; u=os.environ.get("API_URL","http://localhost:8000"); sid=os.environ["SESSION_ID"]; ip=os.environ.get("SOURCE_IP",""); q=urllib.parse.urlencode({"source_ip":ip,"size":100}); c=json.loads(urllib.request.urlopen(f"{u}/campaigns?{q}",timeout=10).read()).get("campaigns",[]); print(next((x.get("campaign_id","") for x in c if sid in (x.get("session_ids") or [])),""))')"
export BACKEND_CAMPAIGN_ID

echo ">> requesting LIVE hybrid detection and verifying persisted lineage"
export API_KEY
python3 - <<'PY'
import json, os, sys, urllib.error, urllib.request
base = os.environ.get("API_URL", "http://localhost:8000")
sid = os.environ["SESSION_ID"]
headers = {"X-API-Key": os.environ["API_KEY"]}
def request(url, method="GET"):
    req = urllib.request.Request(url, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read())
try:
    result = request(f"{base}/detect/hybrid/{sid}", "POST")
    detection_id = result.get("detection_id")
    if not detection_id or not result.get("persisted"):
        raise RuntimeError("hybrid detector did not persist a detection; scenario must trigger a signal")
    if result.get("session_id") != sid:
        raise RuntimeError("detection session_id does not match the generated session")
    lineage = request(f"{base}/detections/{detection_id}/lineage")
    chain = lineage.get("lineage_chain", [])
    if lineage.get("session_id") != sid or lineage.get("detection_id") != detection_id:
        raise RuntimeError("lineage endpoint returned mismatched detection/session identity")
    if "session" not in chain or "features" not in chain or lineage.get("session_event_count", 0) < 1:
        raise RuntimeError("lineage does not connect detection to a session containing events and features")
    if lineage.get("campaign_id") != os.environ.get("BACKEND_CAMPAIGN_ID") or "campaign" not in chain:
        raise RuntimeError("detection lineage does not link the correlated backend campaign")
    print(json.dumps({"detection_id": detection_id, "session_id": sid,
                      "campaign_id": lineage.get("campaign_id"), "detector": result.get("detector_version", result.get("engine")),
                      "prediction": result.get("label"), "decision_source": (result.get("evidence") or {}).get("contributed_signals"),
                      "decision_reason": result.get("explanation"), "ground_truth_label": os.environ.get("SCENARIO", "ssh-bruteforce"),
                      "ground_truth_source": "SCENARIO_GROUND_TRUTH", "lineage_chain": chain,
                      "session_event_count": lineage["session_event_count"]}))
    print("OK: persisted detection lineage links campaign, session, events, features, and detector output")
except (urllib.error.URLError, RuntimeError, KeyError, ValueError) as exc:
    print(f"FAIL: detection lineage verification: {exc}", file=sys.stderr)
    sys.exit(1)
PY
echo "=== E2E PASSED ==="
echo "  attacker_campaign_tag: $CAMPAIGN_ID"
echo "  backend_campaign_id: $BACKEND_CAMPAIGN_ID"
echo "  run_id:      $RUN_ID"
echo "  event_id:    $EVENT_ID"
echo "  session_id:  $SESSION_ID"
