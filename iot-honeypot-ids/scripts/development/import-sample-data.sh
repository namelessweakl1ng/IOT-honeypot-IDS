#!/usr/bin/env bash
# Import clearly-labeled SYNTHETIC sample telemetry into Elasticsearch so
# PC1 development can continue without a Pi connected.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "=== Importing SYNTHETIC sample data ==="

# Generate sample session-level events clearly labeled as synthetic
python3 - <<'PY'
import json, os, random, sys, uuid
from datetime import datetime, timezone, timedelta

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("elasticsearch python client not installed. Run scripts/setup/init.sh first.", file=sys.stderr)
    sys.exit(2)

es_url = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200")
es_user = os.environ.get("ES_USER", "elastic")
es_pass = os.environ.get("ES_PASS") or os.environ.get("ELASTIC_PASSWORD", "")
if not es_pass:
    print("ERROR: set ES_PASS or ELASTIC_PASSWORD env var", file=sys.stderr)
    sys.exit(2)

es = Elasticsearch(es_url, basic_auth=(es_user, es_pass), request_timeout=10)

if not es.ping():
    print(f"ERROR: cannot reach Elasticsearch at {es_url}", file=sys.stderr)
    sys.exit(2)

# Generate 5 synthetic attack sessions — all clearly labeled.
labels = ["reconnaissance", "brute_force", "default_credentials",
          "command_injection", "path_traversal"]

rng = random.Random(42)
now = datetime.now(timezone.utc)

for i, label in enumerate(labels):
    session_id = str(uuid.uuid4())
    src_ip = f"10.0.0.{i+10}"
    start = now - timedelta(minutes=20 - i)
    n_events = rng.randint(5, 20)
    for j in range(n_events):
        ev = {
            "@timestamp": (start + timedelta(seconds=j)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "event_id": str(uuid.uuid4()),
            "session_id": session_id,
            "source": {"ip": src_ip, "port": rng.randint(40000, 60000)},
            "destination": {"ip": "192.168.1.50", "port": 8080},
            "device": {"id": "camera-01", "type": "camera", "hostname": "iot-bridge-01", "container": "pi-camera"},
            "protocol": "http",
            "event": {"type": "http_request", "category": "network",
                      "action": "synthetic_replay"},
            "authentication": {"attempted": False, "username": None, "success": False},
            "http": {
                "method": "GET", "uri": f"/{label}/{j}",
                "status": 200, "user_agent": "synthetic-replay",
                "bytes_in": 0, "bytes_out": 100,
            },
            "honeypot": {"name": "camera", "container": "pi-camera"},
            "attack": {
                "session_id": session_id,
                "stage": "reconnaissance" if label == "reconnaissance" else "execution",
                "classification": label if label != "reconnaissance" else None,
                "confidence": 0.5,
            },
            "labels": {"source": "SYNTHETIC", "campaign_id": f"syn-campaign-{i:04d}"},
            "tags": ["SYNTHETIC", "REPLAY"],
        }
        # index with explicit event_id as document id
        es.index(index=f"honeypot-events-synthetic-{now.strftime('%Y.%m.%d')}", id=ev["event_id"], document=ev)
    print(f"  indexed {n_events} synthetic events for session {session_id} (label={label})")

print("OK: synthetic data imported. Events are tagged SYNTHETIC + REPLAY.")
PY
