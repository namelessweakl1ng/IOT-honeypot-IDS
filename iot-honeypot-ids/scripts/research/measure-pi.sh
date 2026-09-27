#!/usr/bin/env bash
# Capture real host/container readings; no estimates or synthesized values.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-$ROOT/research/measurements/resources-$(date -u +%Y%m%dT%H%M%SZ)-$(hostname).csv}"
SAMPLES="${2:-60}"
INTERVAL="${3:-1}"
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then echo "Usage: $0 [output.csv] [samples] [interval-seconds]"; exit 0; fi
[[ "$SAMPLES" =~ ^[1-9][0-9]*$ && "$INTERVAL" =~ ^[1-9][0-9]*$ ]] || { echo "samples and interval must be positive integers" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")"
printf 'timestamp_utc,host,cpu_busy_pct,ram_used_bytes,ram_total_bytes,temperature_c,load1,disk_root_used_bytes,disk_root_total_bytes,rx_bytes,tx_bytes,container_stats\n' > "$OUT"
for ((i=0; i<SAMPLES; i++)); do
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  host="$(hostname)"
  read -r cpu user nice system idle iowait irq softirq steal rest < /proc/stat
  total1=$((user+nice+system+idle+iowait+irq+softirq+steal)); busy1=$((total1-idle-iowait))
  mem_total=$(awk '/MemTotal:/ {print $2*1024}' /proc/meminfo)
  mem_available=$(awk '/MemAvailable:/ {print $2*1024}' /proc/meminfo)
  sleep "$INTERVAL"
  read -r cpu user nice system idle iowait irq softirq steal rest < /proc/stat
  total2=$((user+nice+system+idle+iowait+irq+softirq+steal)); busy2=$((total2-idle-iowait))
  cpu_pct=$(awk -v b1="$busy1" -v b2="$busy2" -v t1="$total1" -v t2="$total2" 'BEGIN { d=t2-t1; if(d>0) printf "%.2f",100*(b2-b1)/d; else printf "" }')
  temp=""
  if command -v vcgencmd >/dev/null 2>&1; then temp=$(vcgencmd measure_temp | sed -E "s/.*=([0-9.]+)'C/\1/"); fi
  load=$(awk '{print $1}' /proc/loadavg)
  read -r disk_used disk_total < <(df -B1 / | awk 'NR==2 {print $3,$2}')
  read -r rx tx < <(awk -F'[: ]+' 'NR>2 && $2 !~ /lo/ {rx+=$3; tx+=$11} END {print rx,tx}' /proc/net/dev)
  containers=""
  if command -v docker >/dev/null 2>&1; then containers=$(docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}' 2>/dev/null | tr '\n' ';' || true); fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"%s"\n' "$timestamp" "$host" "$cpu_pct" "$((mem_total-mem_available))" "$mem_total" "$temp" "$load" "$disk_used" "$disk_total" "$rx" "$tx" "${containers//\"/\"\"}" >> "$OUT"
done
echo "Recorded $SAMPLES samples in $OUT. These are host measurements; retain hardware, workload, and command context with the artifact."
