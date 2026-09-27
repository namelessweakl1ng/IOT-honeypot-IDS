#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RAW_DIR="${IOT23_DATA_DIR:-}"
ARCHIVE_URL="https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/iot_23_datasets_small.tar.gz"
DOWNLOAD=0
while (($#)); do
  case "$1" in
    --download) DOWNLOAD=1 ;;
    -h|--help) echo "Usage: IOT23_DATA_DIR=/external/path ./scripts/research/prepare-iot23.sh [--download]"; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
for command in python3 tar sha256sum; do
  command -v "$command" >/dev/null || { echo "ERROR: required command not found: $command" >&2; exit 2; }
done
if [[ "$DOWNLOAD" == 1 ]]; then
  command -v curl >/dev/null || { echo "ERROR: --download requires curl" >&2; exit 2; }
  [[ -n "$RAW_DIR" ]] || { echo "ERROR: set IOT23_DATA_DIR outside this repository before --download" >&2; exit 2; }
  mkdir -p "$RAW_DIR"
  RAW_ABS="$(cd "$RAW_DIR" && pwd -P)"
  case "$RAW_ABS/" in
    "$ROOT/"*) echo "ERROR: raw IoT-23 data must be outside the Git checkout: $RAW_ABS" >&2; exit 4 ;;
  esac
  ARCHIVE="${IOT23_ARCHIVE:-$RAW_DIR/iot_23_datasets_small.tar.gz}"
  [[ -s "$ARCHIVE" ]] || curl --fail --location --retry 3 "$ARCHIVE_URL" --output "$ARCHIVE"
  if [[ -n "${IOT23_SHA256:-}" ]]; then
    printf '%s  %s\n' "$IOT23_SHA256" "$ARCHIVE" | sha256sum --check --status || { echo "ERROR: IoT-23 archive SHA-256 mismatch" >&2; exit 3; }
  else
    echo "NOTICE: source publishes no archive checksum; recorded hash is integrity metadata, not an authenticity check."
  fi
  sha256sum "$ARCHIVE" > "$RAW_DIR/download.sha256"
  tar -xzf "$ARCHIVE" -C "$RAW_DIR"
fi
if [[ -z "$RAW_DIR" || ! -d "$RAW_DIR" ]]; then
  echo "ERROR: IoT-23 data unavailable. Set IOT23_DATA_DIR to extracted files containing <scenario>/bro/conn.log.labeled. Synthetic fallback is disabled." >&2
  exit 4
fi
RAW_ABS="$(cd "$RAW_DIR" && pwd -P)"
case "$RAW_ABS/" in
  "$ROOT/"*) echo "ERROR: raw IoT-23 data must be outside the Git checkout: $RAW_ABS" >&2; exit 4 ;;
esac
if [[ -n "${IOT23_SHA256:-}" && "$DOWNLOAD" == 0 ]]; then
  [[ -n "${IOT23_ARCHIVE:-}" && -f "$IOT23_ARCHIVE" ]] || { echo "ERROR: IOT23_SHA256 is set, but IOT23_ARCHIVE does not name a local archive to verify" >&2; exit 3; }
  printf '%s  %s\n' "$IOT23_SHA256" "$IOT23_ARCHIVE" | sha256sum --check --status || { echo "ERROR: IoT-23 archive SHA-256 mismatch" >&2; exit 3; }
fi
PYTHONPATH="$ROOT/model-lab${PYTHONPATH:+:$PYTHONPATH}" python3 "$ROOT/scripts/research/prepare_iot23.py" --input "$RAW_DIR" --output "$ROOT/research/datasets/iot23/prepared"
