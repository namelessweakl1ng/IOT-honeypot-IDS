#!/usr/bin/env sh
set -eu

MANAGER=/opt/trapsig/sensor/scripts/manage.sh
case "${SSH_ORIGINAL_COMMAND:-}" in
  status) exec "$MANAGER" status ;;
  "start cowrie") exec "$MANAGER" start cowrie ;;
  "stop cowrie") exec "$MANAGER" stop cowrie ;;
  "restart cowrie") exec "$MANAGER" restart cowrie ;;
  "start camera") exec "$MANAGER" start camera ;;
  "stop camera") exec "$MANAGER" stop camera ;;
  "restart camera") exec "$MANAGER" restart camera ;;
  "start iot-service") exec "$MANAGER" start iot-service ;;
  "stop iot-service") exec "$MANAGER" stop iot-service ;;
  "restart iot-service") exec "$MANAGER" restart iot-service ;;
  "start mqtt") exec "$MANAGER" start mqtt ;;
  "stop mqtt") exec "$MANAGER" stop mqtt ;;
  "restart mqtt") exec "$MANAGER" restart mqtt ;;
  "start router") exec "$MANAGER" start router ;;
  "stop router") exec "$MANAGER" stop router ;;
  "restart router") exec "$MANAGER" restart router ;;
  *) echo "Denied: unsupported TRAPSIG management command" >&2; exit 2 ;;
esac
