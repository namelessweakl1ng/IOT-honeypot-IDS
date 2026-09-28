#!/usr/bin/env sh
set -eu

MANAGER=/opt/trapsig/sensor/scripts/manage.sh
case "${SSH_ORIGINAL_COMMAND:-}" in
  "$MANAGER status") exec "$MANAGER" status ;;
  "$MANAGER start cowrie") exec "$MANAGER" start cowrie ;;
  "$MANAGER stop cowrie") exec "$MANAGER" stop cowrie ;;
  "$MANAGER restart cowrie") exec "$MANAGER" restart cowrie ;;
  "$MANAGER start camera") exec "$MANAGER" start camera ;;
  "$MANAGER stop camera") exec "$MANAGER" stop camera ;;
  "$MANAGER restart camera") exec "$MANAGER" restart camera ;;
  "$MANAGER start iot-service") exec "$MANAGER" start iot-service ;;
  "$MANAGER stop iot-service") exec "$MANAGER" stop iot-service ;;
  "$MANAGER restart iot-service") exec "$MANAGER" restart iot-service ;;
  "$MANAGER start mqtt") exec "$MANAGER" start mqtt ;;
  "$MANAGER stop mqtt") exec "$MANAGER" stop mqtt ;;
  "$MANAGER restart mqtt") exec "$MANAGER" restart mqtt ;;
  "$MANAGER start router") exec "$MANAGER" start router ;;
  "$MANAGER stop router") exec "$MANAGER" stop router ;;
  "$MANAGER restart router") exec "$MANAGER" restart router ;;
  *) echo "Denied: unsupported TRAPSIG management command" >&2; exit 2 ;;
esac
