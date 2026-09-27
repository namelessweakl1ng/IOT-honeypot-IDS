#!/usr/bin/env bash
set -euo pipefail
ID="${1:-}"
[[ "$ID" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "Usage: $0 <campaign_id>" >&2; exit 2; }
API_URL="${API_URL:-http://localhost:8000}"
curl --fail --silent --show-error --max-time 10 "$API_URL/campaigns/$ID" | { if command -v jq >/dev/null 2>&1; then jq '{campaign_id, source, session_ids, event_count, started_at, ended_at, campaign_status, sessions: [.sessions[]? | {session_id, campaign_id, event_count, event_ids}]}'; else cat; fi; }
