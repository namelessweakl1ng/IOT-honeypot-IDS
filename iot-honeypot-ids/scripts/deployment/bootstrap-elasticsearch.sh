#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TPL_DIR="${REPO_ROOT}/dashboard/elasticsearch/index-templates"
ILM_DIR="${REPO_ROOT}/dashboard/elasticsearch/ilm"
ES_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"
ES_USER="${ELASTIC_USER:-elastic}"
ES_PASS="${ELASTIC_PASSWORD:-}"
if [ -z "$ES_PASS" ]; then echo "ERROR: ELASTIC_PASSWORD is required" >&2; exit 1; fi
CURL_AUTH=(-u "${ES_USER}:${ES_PASS}")
log() { echo "[bootstrap-es] $*"; }
err() { echo "[bootstrap-es] ERROR: $*" >&2; }
log "waiting for Elasticsearch at ${ES_URL} ..."
healthy=0
for i in $(seq 1 60); do
  if curl -sS "${CURL_AUTH[@]}" --max-time 5 "${ES_URL}/_cluster/health?wait_for_status=yellow&timeout=2s" | grep -q '"status"'; then healthy=1; break; fi
  sleep 5
done
if [ "$healthy" -ne 1 ]; then err "Elasticsearch did not become healthy"; exit 1; fi
log "Elasticsearch is healthy"
install_template() {
  local name="$1"; local file="${TPL_DIR}/${name}.json"
  if [ ! -f "$file" ]; then err "template file not found: $file"; exit 2; fi
  log "installing index template: ${name}"
  curl -sS -o /dev/null -w "%{http_code}" -X PUT "${CURL_AUTH[@]}" -H 'Content-Type: application/json' --data-binary "@${file}" "${ES_URL}/_index_template/${name}" | grep -qE '^(200|201)$' || { err "failed to install template ${name}"; exit 2; }
}
install_template honeypot-events
install_template honeypot-sessions
install_template honeypot-campaigns
install_template honeypot-detections
install_template honeypot-errors
install_template honeypot-training
ILM_FILE="${ILM_DIR}/honeypot-events-policy.json"
if [ -f "$ILM_FILE" ]; then
  log "installing ILM policy: honeypot-events-policy"
  curl -sS -o /dev/null -w "%{http_code}" -X PUT "${CURL_AUTH[@]}" -H 'Content-Type: application/json' --data-binary "@${ILM_FILE}" "${ES_URL}/_ilm/policy/honeypot-events-policy" | grep -qE '^(200|201)$' || { err "failed to install ILM policy"; exit 2; }
fi
ES_PASS="${ES_PASS}" python3 - <<'PY' || exit 3
import json, os, sys, urllib.request, base64
es_url = os.environ["ES_URL"]; es_user = os.environ["ES_USER"]; es_pass = os.environ["ES_PASS"]
auth = base64.b64encode(f"{es_user}:{es_pass}".encode()).decode()
headers = {"Authorization": f"Basic {auth}"}
def get_json(path):
    req = urllib.request.Request(f"{es_url}{path}", headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read())
def find_field_type(props, field_path):
    cur = props
    for p in field_path.split("."):
        if not isinstance(cur, dict) or p not in cur: return None
        cur = cur[p]
        if isinstance(cur, dict) and "properties" in cur and "type" not in cur: cur = cur["properties"]
    return cur.get("type") if isinstance(cur, dict) else None
def assert_field(name, props, field, expected_type):
    actual = find_field_type(props, field)
    if actual is None: print(f"ERROR: template '{name}' missing field '{field}'", file=sys.stderr); sys.exit(3)
    if actual != expected_type: print(f"ERROR: template '{name}' field '{field}' has type '{actual}', expected '{expected_type}'", file=sys.stderr); sys.exit(3)
    print(f"  ok: {name} . {field} -> {expected_type}")
print("[bootstrap-es] verifying template mappings (structural)")
assert_field("honeypot-events", get_json("/_index_template/honeypot-events")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "source.ip", "ip")
assert_field("honeypot-events", get_json("/_index_template/honeypot-events")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "destination.ip", "ip")
assert_field("honeypot-events", get_json("/_index_template/honeypot-events")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "session_id", "keyword")
assert_field("honeypot-events", get_json("/_index_template/honeypot-events")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "event_id", "keyword")
assert_field("honeypot-events", get_json("/_index_template/honeypot-events")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "@timestamp", "date")
assert_field("honeypot-events", get_json("/_index_template/honeypot-events")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "ingested_at", "date")
assert_field("honeypot-events", get_json("/_index_template/honeypot-events")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "timestamp_source", "keyword")
assert_field("honeypot-sessions", get_json("/_index_template/honeypot-sessions")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "session_id", "keyword")
assert_field("honeypot-sessions", get_json("/_index_template/honeypot-sessions")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "event_ids", "keyword")
assert_field("honeypot-sessions", get_json("/_index_template/honeypot-sessions")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "campaign_id", "keyword")
assert_field("honeypot-campaigns", get_json("/_index_template/honeypot-campaigns")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "campaign_id", "keyword")
assert_field("honeypot-campaigns", get_json("/_index_template/honeypot-campaigns")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "session_ids", "keyword")
assert_field("honeypot-errors", get_json("/_index_template/honeypot-errors")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "error_id", "keyword")
assert_field("honeypot-errors", get_json("/_index_template/honeypot-errors")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "stage", "keyword")
assert_field("honeypot-errors", get_json("/_index_template/honeypot-errors")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "reason", "keyword")
assert_field("honeypot-detections", get_json("/_index_template/honeypot-detections")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "detector_version", "keyword")
assert_field("honeypot-detections", get_json("/_index_template/honeypot-detections")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "model_id", "keyword")
assert_field("honeypot-detections", get_json("/_index_template/honeypot-detections")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "persisted", "boolean")
assert_field("honeypot-detections", get_json("/_index_template/honeypot-detections")["index_templates"][0]["index_template"]["template"]["mappings"]["properties"], "detector_config_fingerprint", "keyword")
print("[bootstrap-es] verifying ILM policy (structural)")
ilm_body = get_json("/_ilm/policy/honeypot-events-policy")
policy = ilm_body.get("honeypot-events-policy", {}).get("policy") or ilm_body.get("policy")
if not isinstance(policy, dict):
    print("ERROR: ILM policy response missing 'policy' object", file=sys.stderr); sys.exit(3)
for f in ("default_state", "states", "ism_template", "state_name"):
    assert f not in policy, f"ILM policy contains OpenSearch ISM field '{f}'"
phases = policy.get("phases")
if not isinstance(phases, dict):
    print("ERROR: ILM policy missing 'phases' object", file=sys.stderr); sys.exit(3)
assert "hot" in phases
print("  ok: phases.hot present")
delete_phase = phases.get("delete")
if not isinstance(delete_phase, dict):
    print("ERROR: ILM policy missing 'phases.delete'", file=sys.stderr); sys.exit(3)
assert "delete" in delete_phase.get("actions", {})
assert delete_phase.get("min_age")
print(f"  ok: phases.delete present (min_age={delete_phase.get('min_age')}, action=delete)")
print("[bootstrap-es] verifying no dangling honeypot-default pipeline")
tpl = get_json("/_index_template/honeypot-events")
assert "honeypot-default" not in json.dumps(tpl)
print("[bootstrap-es] Elasticsearch bootstrap complete")
PY
log "Elasticsearch bootstrap complete"
