#!/usr/bin/env bash
# Pass 2 Phase 13: Failure tests against live FastAPI backend.
# Starts uvicorn, exercises every failure path, kills uvicorn.
set -u
cd /home/z/my-project/iot-honeypot-ids/dashboard/api

PI_IP="" PI_SSH_USER="" ELASTICSEARCH_URL=http://localhost:9200 \
  python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level warning > /tmp/trapsig-api.log 2>&1 &
UVICORN_PID=$!
sleep 3

# The default API_SECRET_KEY when .env is absent is "dev-only-insecure-key"
# (from settings.api_secret_key). Real deployments override via env var.
API_KEY="dev-only-insecure-key"

PASS=0
FAIL=0
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  PASS  $name (HTTP $actual)"
    PASS=$((PASS+1))
  else
    echo "  FAIL  $name (expected $expected, got $actual)"
    FAIL=$((FAIL+1))
  fi
}

echo "=== Phase 13: Failure tests against live FastAPI ==="

# Test 1: No API key → 401
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST http://127.0.0.1:8000/honeypots/cowrie-01/start)
check "POST /honeypots/cowrie-01/start without API key → 401" "401" "$CODE"

# Test 2: Pi not configured → 503
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST http://127.0.0.1:8000/honeypots/cowrie-01/start -H "X-API-Key: $API_KEY")
check "POST /honeypots/cowrie-01/start with API key, Pi NOT_CONFIGURED → 503" "503" "$CODE"

# Test 3: Unknown honeypot → 404
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST http://127.0.0.1:8000/honeypots/nonexistent/start -H "X-API-Key: $API_KEY")
check "POST /honeypots/nonexistent/start → 404" "404" "$CODE"

# Test 4: /replay with non-lab target → 400
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST http://127.0.0.1:8000/replay -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{"scenario_id":"ssh-bruteforce","target":"8.8.8.8"}')
check "POST /replay target=8.8.8.8 (non-lab) → 400" "400" "$CODE"

# Test 5: /replay without API key → 401
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST http://127.0.0.1:8000/replay -H "Content-Type: application/json" -d '{"scenario_id":"ssh-bruteforce","target":"192.168.1.50"}')
check "POST /replay without API key → 401" "401" "$CODE"

# Test 6: /training without API key → 401
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST http://127.0.0.1:8000/training -H "Content-Type: application/json" -d '{"algorithm":"random_forest"}')
check "POST /training without API key → 401" "401" "$CODE"

# Test 7: /health always accessible (no auth)
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:8000/health)
check "GET /health (no auth) → 200" "200" "$CODE"

# Test 8: GET /honeypots (no auth, read-only)
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:8000/honeypots)
check "GET /honeypots (no auth) → 200" "200" "$CODE"

# Test 9: /stats when ES down → 200 with degraded status
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 http://127.0.0.1:8000/stats)
check "GET /stats (ES down) → 200" "200" "$CODE"
STATS_BODY=$(curl -s --max-time 30 http://127.0.0.1:8000/stats)
echo "  /stats body: $STATS_BODY"

# Test 10: /events when ES down → 200 with empty hits
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 http://127.0.0.1:8000/events?size=1)
check "GET /events (ES down) → 200" "200" "$CODE"

# Test 11: /sessions when ES down → 200 with empty sessions
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 http://127.0.0.1:8000/sessions?size=1)
check "GET /sessions (ES down) → 200" "200" "$CODE"

# Test 12: /detections when ES down → 200 with empty detections
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 http://127.0.0.1:8000/detections?size=1)
check "GET /detections (ES down) → 200" "200" "$CODE"

# Test 13: /models (read-only, no ES needed)
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:8000/models)
check "GET /models → 200" "200" "$CODE"

# Test 14: /experiments (read-only, no ES needed)
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:8000/experiments)
check "GET /experiments → 200" "200" "$CODE"

# Test 15: Secret sweep — no secrets in /honeypots response
BODY=$(curl -s --max-time 5 http://127.0.0.1:8000/honeypots)
if echo "$BODY" | grep -qE "192\.168\.1\.50|pi@|id_ed25519|API_SECRET_KEY|dev-only-insecure-key"; then
  echo "  FAIL  /honeypots response contains secrets"
  FAIL=$((FAIL+1))
else
  echo "  PASS  /honeypots response contains no secrets"
  PASS=$((PASS+1))
fi

# Test 16: /honeypots response structure
BODY=$(curl -s --max-time 5 http://127.0.0.1:8000/honeypots)
echo "$BODY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
assert data['pi_status'] == 'NOT_CONFIGURED', f\"expected NOT_CONFIGURED, got {data['pi_status']}\"
assert data['pi_reachable'] is False
assert data['pi_configured'] is False
assert len(data['honeypots']) == 3
for hp in data['honeypots']:
    assert hp['state'] == 'not_configured', f\"{hp['id']} state={hp['state']}\"
    assert hp['container_exists'] is False
print('  PASS  /honeypots structure: NOT_CONFIGURED + 3 honeypots all not_configured')
" 2>&1
if [ $? -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="

kill $UVICORN_PID 2>/dev/null
wait $UVICORN_PID 2>/dev/null
exit $FAIL
