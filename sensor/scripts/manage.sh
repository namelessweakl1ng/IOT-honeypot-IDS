#!/usr/bin/env sh
set -eu
action=${1:?action required}
cd "$(dirname "$0")/.."
if [ "$action" = status ]; then
  [ "$#" -eq 1 ] || { echo "status takes no arguments" >&2; exit 2; }
  for service in cowrie camera iot-service mqtt router; do
    container=$(docker compose ps -q "$service")
    if [ -n "$container" ] && [ "$(docker inspect -f '{{.State.Running}}' "$container")" = true ]; then
      echo "$service=running"
    else
      echo "$service=stopped"
    fi
  done
  exit 0
fi
service=${2:?service required}
[ "$#" -eq 2 ] || { echo "too many arguments" >&2; exit 2; }
case "$action" in start|stop|restart) ;; *) echo "unsupported action" >&2; exit 2;; esac
case "$service" in cowrie|camera|iot-service|mqtt|router) ;; *) echo "unknown honeypot" >&2; exit 2;; esac
docker compose "$action" "$service"
