#!/bin/sh
set -eu
base=${ELASTICSEARCH_URL:-http://elasticsearch:9200}
for file in /templates/*.json; do
  name=$(basename "$file" .json)
  curl -fsS -X PUT -H 'Content-Type: application/json' --data-binary "@$file" "$base/_index_template/$name"
done
# Templates do not update existing indices. This known-name-only, idempotent update
# fixes the single-node replica setting without recreating or deleting any data.
curl -fsS -X PUT -H 'Content-Type: application/json' \
  --data '{"index":{"number_of_replicas":0}}' \
  "$base/trapsig-events-*,trapsig-dead-letter-*,trapsig-sessions,trapsig-detections,trapsig-experiments/_settings?allow_no_indices=true&ignore_unavailable=true&expand_wildcards=all"
