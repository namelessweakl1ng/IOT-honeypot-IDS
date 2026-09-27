#!/usr/bin/env bash
set -euo pipefail
ID="${1:-}"
[[ "$ID" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "Usage: $0 <detection_id>" >&2; exit 2; }
API_URL="${API_URL:-http://localhost:8000}"
curl --fail --silent --show-error --max-time 15 "$API_URL/detections/$ID" | { if command -v jq >/dev/null 2>&1; then jq '{detection_id: .detection.detection_id, session_id: .detection.session_id, campaign_id: .detection.campaign_id, detector: .detection.detector_version, prediction: .detection.label, decision_source: (.detection.evidence.contributed_signals // [.detection.engine]), decision_reason: .detection.explanation, ground_truth_label: .session.ground_truth_label, ground_truth_source: .session.ground_truth_source, event_ids: [.events[]?.event_id], feature_schema_version: .features.feature_schema_version, campaign_found: (.campaign != null), detection: .detection}'; else cat; fi; }
