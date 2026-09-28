#!/usr/bin/env sh
set -eu
action=${1:?action required}; service=${2:?service required}
case "$action" in start|stop|restart) ;; *) echo "unsupported action" >&2; exit 2;; esac
case "$service" in cowrie|camera|iot-service|mqtt|router) ;; *) echo "unknown honeypot" >&2; exit 2;; esac
cd "$(dirname "$0")/.." && docker compose "$action" "$service"
