#!/bin/sh
set -eu
base=${ELASTICSEARCH_URL:-http://elasticsearch:9200}
for file in /templates/*.json; do
  name=$(basename "$file" .json)
  curl -fsS -X PUT -H 'Content-Type: application/json' --data-binary "@$file" "$base/_index_template/$name"
done
