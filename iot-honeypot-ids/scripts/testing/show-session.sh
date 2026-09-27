#!/usr/bin/env bash
set -euo pipefail
ID="${1:-}"
[[ "$ID" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "Usage: $0 <session_id>" >&2; exit 2; }
API_URL="${API_URL:-http://localhost:8000}"
curl --fail --silent --show-error --max-time 10 "$API_URL/sessions/$ID" | { if command -v jq >/dev/null 2>&1; then jq '{session_id, campaign_id, started_at, ended_at, source, classification, ground_truth_label, ground_truth_source, event_count, event_ids, events}'; else cat; fi; }
