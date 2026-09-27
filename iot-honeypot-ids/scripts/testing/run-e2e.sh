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
RUN_ID="run-$(date -u +%Y%m%dT%H%M%SZ)-$(printf '%06x' $((RANDOM % 16777215)))"
ES_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"
ES_PASS="${ELASTIC_PASSWORD:-}"
API_URL="${API_URL:-http://localhost:8000}"
API_KEY="${API_SECRET_KEY:-}"
[ -n "$API_KEY" ] || { echo "ERROR: API_SECRET_KEY is required for LIVE detection" >&2; exit 2; }
export ES_URL ES_PASS TEST_START_ISO API_URL

echo "=== E2E: $SCENARIO against $TARGET (expect honeypot: auto-detected) ==="
echo "campaign_id: $CAMPAIGN_ID"
echo "run_id:      $RUN_ID"
echo "test_start:  $TEST_START_ISO"

echo ">> launching attacker scenario"
./attacker/run-scenario.sh --target "$TARGET" --scenario "$SCENARIO" --campaign-id "$CAMPAIGN_ID" || true

echo ">> polling ES for new event (timeout 60s, every 2s)"
NEW_EVENT_DOC=""
elapsed=0
while [ "$elapsed" -lt 60 ]; do
  NEW_EVENT_DOC="$(python3 - "$@" <<PY || true
import os, sys, json
try:
    from elasticsearch import Elasticsearch
except ImportError:
    sys.exit(2)
es = Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"), basic_auth=("elastic", os.environ.get("ES_PASS", "")), request_timeout=10)
test_start = os.environ.get("TEST_START_ISO", "")
q = {"query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": test_start}}}]}}, "sort": [{"@timestamp": "desc"}], "size": 5}
resp = es.search(index="honeypot-events-*", body=q)
body = resp.body if hasattr(resp, "body") else resp
hits = body.get("hits", {}).get("hits", [])
if hits:
    print(json.dumps(hits[0]["_source"]))
    sys.exit(0)
sys.exit(2)
PY
)"
  rc=$?
  if [ "$rc" -eq 0 ] && [ -n "$NEW_EVENT_DOC" ]; then
    echo ">> found new event in ES"
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
export API_URL EVENT_ID SESSION_ID
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
    if "session" not in chain or lineage.get("session_event_count", 0) < 1:
        raise RuntimeError("lineage does not connect detection to a session containing events")
    print(json.dumps({"detection_id": detection_id, "session_id": sid,
                      "campaign_id": lineage.get("campaign_id"), "lineage_chain": chain,
                      "session_event_count": lineage["session_event_count"]}))
    print("OK: persisted detection lineage links the detection, session, and events")
except (urllib.error.URLError, RuntimeError, KeyError, ValueError) as exc:
    print(f"FAIL: detection lineage verification: {exc}", file=sys.stderr)
    sys.exit(1)
PY
echo "=== E2E PASSED ==="
echo "  campaign_id: $CAMPAIGN_ID"
echo "  run_id:      $RUN_ID"
echo "  event_id:    $EVENT_ID"
echo "  session_id:  $SESSION_ID"
