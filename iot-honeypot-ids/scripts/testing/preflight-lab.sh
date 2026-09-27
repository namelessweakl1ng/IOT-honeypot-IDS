#!/usr/bin/env bash
# Read-only preflight. Missing configuration is SKIPPED, not a successful probe.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PASS=0; FAIL=0; SKIPPED=0
report() { local state="$1" name="$2" detail="${3:-}"; printf '%-7s %s%s\n' "$state" "$name" "${detail:+ — $detail}"; case "$state" in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; SKIPPED) SKIPPED=$((SKIPPED+1));; esac; }
for command in curl python3; do
  if command -v "$command" >/dev/null 2>&1; then report PASS "command:$command"; else report FAIL "command:$command" "required"; fi
done
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then report PASS docker "daemon reachable"; else report FAIL docker "CLI present, daemon unavailable"; fi
else report SKIPPED docker "not installed on this host"; fi

PI_HOST="${PI_IP:-${PI_HOST:-}}"
ANALYSIS_HOST="${ANALYSIS_HOST:-${CENTRAL_SERVER_IP:-}}"
tcp_check() {
  local label="$1" host="$2" port="$3"
  if [[ -z "$host" ]]; then report SKIPPED "$label" "host not configured"; return; fi
  if python3 -c 'import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3); s.close()' "$host" "$port" >/dev/null 2>&1; then report PASS "$label" "$host:$port"; else report FAIL "$label" "$host:$port unreachable"; fi
}
http_check() {
  local label="$1" url="$2" code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 "$url" 2>/dev/null || true)"
  if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then report PASS "$label" "HTTP $code"; elif [[ "$code" == 401 || "$code" == 403 ]]; then report PASS "$label" "endpoint reachable; HTTP $code auth required"; else report FAIL "$label" "HTTP ${code:-unreachable}"; fi
}
if [[ -z "$PI_HOST" ]]; then report SKIPPED pi "set PI_IP or PI_HOST"; else
  tcp_check pi_ssh "$PI_HOST" "${PI_SSH_PORT:-22}"
  tcp_check cowrie_ssh "$PI_HOST" "${COWRIE_SSH_PORT:-2222}"
  tcp_check camera_http "$PI_HOST" "${CAMERA_HTTP_PORT:-8080}"
  tcp_check iot_service "$PI_HOST" "${IOT_SERVICE_PORT:-9000}"
  if [[ -n "${PI_SSH_USER:-}" ]] && command -v ssh >/dev/null 2>&1; then
    if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=yes "${PI_SSH_USER}@${PI_HOST}" 'docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1' >/dev/null 2>&1; then report PASS pi_docker "remote Docker/Compose available"; else report FAIL pi_docker "SSH reachable but remote Docker/Compose unavailable or key not configured"; fi
  else report SKIPPED pi_docker "set PI_SSH_USER and configure noninteractive SSH to verify remotely"; fi
fi
if [[ -z "$ANALYSIS_HOST" ]]; then report SKIPPED analysis_host "set ANALYSIS_HOST or CENTRAL_SERVER_IP"; else
  tcp_check logstash_beats "$ANALYSIS_HOST" "${LOGSTASH_BEATS_PORT:-5044}"
fi
ES_URL="${ELASTICSEARCH_URL:-http://${ANALYSIS_HOST:-127.0.0.1}:${ELASTICSEARCH_PORT:-9200}}"
API_URL="${API_URL:-http://${ANALYSIS_HOST:-127.0.0.1}:${API_PORT:-8000}}"
KIBANA_URL="${KIBANA_URL:-http://${ANALYSIS_HOST:-127.0.0.1}:${KIBANA_PORT:-5601}}"
LOGSTASH_URL="${LOGSTASH_URL:-http://${ANALYSIS_HOST:-127.0.0.1}:${LOGSTASH_HTTP_PORT:-9600}}"
if [[ -n "${ELASTIC_PASSWORD:-}" ]]; then
  pass="${ELASTIC_PASSWORD//\\/\\\\}"; pass="${pass//\"/\\\"}"
  code="$(printf 'user = "elastic:%s"\n' "$pass" | curl --config - -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 "$ES_URL/_cluster/health" 2>/dev/null || true)"
  if [[ "$code" =~ ^2[0-9][0-9]$ ]]; then report PASS elasticsearch "authenticated health HTTP $code"; else report FAIL elasticsearch "authenticated health HTTP ${code:-unreachable}"; fi
else
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 "$ES_URL/_cluster/health" 2>/dev/null || true)"
  if [[ "$code" == 401 || "$code" == 403 ]]; then report PASS elasticsearch "reachable; set ELASTIC_PASSWORD to check health"; else report FAIL elasticsearch "HTTP ${code:-unreachable}"; fi
fi
http_check logstash "$LOGSTASH_URL/_node/stats"
http_check kibana "$KIBANA_URL/api/status"
http_check api "$API_URL/health"
printf '\nSummary: PASS=%d FAIL=%d SKIPPED=%d\n' "$PASS" "$FAIL" "$SKIPPED"
[[ "$FAIL" -eq 0 ]]
