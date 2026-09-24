#!/usr/bin/env bash
# Per-container CPU/RAM/network/health/uptime — keeps the Pi debuggable.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! docker compose ps --format json >/dev/null 2>&1; then
  echo "ERROR: docker compose not available or not running." >&2
  exit 1
fi

printf '%-18s %-10s %-10s %-12s %-12s %-10s %-12s\n' \
  "CONTAINER" "STATE" "CPU%" "MEM_USE" "NET_RX" "HEALTH" "UPTIME"
printf '%-18s %-10s %-10s %-12s %-12s %-10s %-12s\n' \
  "--------" "-----" "----" "-------" "------" "------" "------"

# Use docker stats --no-stream for resource usage, joined with ps for state.
mapfile -t CONTAINERS < <(docker compose ps --format '{{.Name}}' 2>/dev/null || true)
if [ "${#CONTAINERS[@]}" -eq 0 ]; then
  echo "(no running containers — did you run ./scripts/start.sh?)"
  exit 0
fi

for c in "${CONTAINERS[@]}"; do
  # State + health
  state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo "?")
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}' "$c" 2>/dev/null || echo "-")
  uptime=$(docker inspect -f '{{.State.StartedAt}}' "$c" 2>/dev/null || echo "?")

  # Resource stats — single shot, no streaming
  stats=$(docker stats --no-stream --format '{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}' "$c" 2>/dev/null || echo "?\t?\t?")
  cpu=$(echo "$stats" | awk -F'\t' '{print $1}')
  mem=$(echo "$stats" | awk -F'\t' '{print $2}')
  net=$(echo "$stats" | awk -F'\t' '{print $3}')

  # Make uptime human-friendly
  if [ "$uptime" != "?" ]; then
    uptime=$(date -u -d "$uptime" +%H:%M 2>/dev/null || echo "$uptime")
  fi

  printf '%-18s %-10s %-10s %-12s %-12s %-10s %-12s\n' \
    "$c" "$state" "${cpu:-?}" "${mem:-?}" "${net:-?}" "$health" "$uptime"
done
echo
echo "Free memory on Pi host:"
free -h | head -2
