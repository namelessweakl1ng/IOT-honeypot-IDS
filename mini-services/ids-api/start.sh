#!/usr/bin/env bash
# Start the IDS API mini-service.
# Uses the iot-honeypot-ids venv so we share the same scikit-learn install
# as the project itself.
set -e
cd "$(dirname "$0")"
VENV=/home/z/my-project/iot-honeypot-ids/.venv/bin/python
if [ ! -x "$VENV" ]; then
  VENV=python3
fi
exec "$VENV" main.py
