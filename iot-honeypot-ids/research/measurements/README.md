# Physical measurement outputs

This directory contains measurement instructions and schemas only; it does not contain fabricated readings. Resource capture writes timestamped CSV to this directory by default:

```bash
./scripts/research/measure-pi.sh
```

The command records host CPU, memory, temperature when `vcgencmd` is available, load, disk, network counters, and Docker container CPU/memory when Docker is reachable. A CSV row records actual sampled values; an unavailable sensor remains blank.

For latency, create a context JSON and a timestamp JSON with actual event timestamps, then use `python3 scripts/research/record-latency.py --context context.json --timestamps timestamps.json --clock-sync-status synchronized`. Set the synchronization flag only after verifying host clock synchronization. Otherwise durations remain `NOT MEASURED`. T0-T9 semantics and context requirements are defined in `physical-validation/measurement-schema.json`.
