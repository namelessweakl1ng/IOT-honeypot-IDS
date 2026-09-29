#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

mkdir -p secrets
: > secrets/pi_ssh_key
: > secrets/known_hosts
chmod 600 secrets/pi_ssh_key secrets/known_hosts

wait_for() {
  local name=$1 url=$2
  for _ in {1..60}; do
    if curl --fail --silent "$url" >/dev/null; then return 0; fi
    sleep 5
  done
  echo "Timed out waiting for $name ($url)" >&2
  return 1
}

docker compose up --detach elasticsearch logstash backend
wait_for Elasticsearch http://127.0.0.1:9200/_cluster/health
wait_for Logstash http://127.0.0.1:9600/_node/pipelines
wait_for backend http://127.0.0.1:8000/health

# Re-run the committed setup container to prove that installation is idempotent.
docker compose run --rm elasticsearch-setup

python - <<'PY'
import json
import urllib.request
from pathlib import Path


def request(path, *, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:9200{path}", data=data, method=method)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as response:
        return json.load(response)


required = {
    "trapsig-events",
    "trapsig-sessions",
    "trapsig-detections",
    "trapsig-experiments",
    "trapsig-dead-letter",
}
templates = request("/_index_template")["index_templates"]
installed = {item["name"] for item in templates}
assert required <= installed, required - installed

request("/trapsig-events-ci-smoke", method="PUT")
mapping = request("/trapsig-events-ci-smoke/_mapping")["trapsig-events-ci-smoke"]["mappings"]["properties"]
assert mapping["@timestamp"]["type"] == "date"
assert mapping["event"]["properties"]["ingested"]["type"] == "date"
assert mapping["source"]["properties"]["ip"]["type"] == "ip"
assert mapping["destination"]["properties"]["ip"]["type"] == "ip"
request("/trapsig-events-ci-smoke", method="DELETE")

request("/trapsig-detections", method="PUT")
detection = request("/trapsig-detections/_mapping")["trapsig-detections"]["mappings"]["properties"]
assert detection["evidence_end_time"]["type"] == "date"
assert detection["detected_at"]["type"] == "date"
request("/trapsig-experiments", method="PUT")
experiment = request("/trapsig-experiments/_mapping")["trapsig-experiments"]["mappings"]["properties"]
assert experiment["scenario_manifest_sha256"]["type"] == "keyword"
assert experiment["ground_truth_valid"]["type"] == "boolean"

pipelines = json.load(urllib.request.urlopen("http://127.0.0.1:9600/_node/pipelines"))["pipelines"]
assert "trapsig" in pipelines, pipelines.keys()
health = json.load(urllib.request.urlopen("http://127.0.0.1:8000/health"))
assert health["backend"] == "healthy" and health["elasticsearch"] in {"green", "yellow"}, health
scenarios = json.load(urllib.request.urlopen("http://127.0.0.1:8000/scenarios"))
expected = len(list(Path("attacks/scenarios").glob("*.yaml")))
assert len(scenarios) == expected, (len(scenarios), expected)
PY
