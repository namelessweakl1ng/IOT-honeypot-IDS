# Pi — Honeypot Fleet

The Raspberry Pi 4 (4 GB RAM, Pi OS Lite 64-bit) is a **sensor only**. It runs
lightweight Docker containers that deceive attackers and emit structured JSON
telemetry. It never runs Elasticsearch, Kibana, or ML workloads.

## What runs here

| Container | Image / build | Purpose |
|---|---|---|
| `cowrie` | `cowrie/cowrie:latest` | SSH/Telnet honeypot, structured JSON |
| `camera` | built from `./honeypots/camera` | HTTP camera/DVR simulator |
| `iot-service` | built from `./honeypots/iot-service` | Lightweight TCP IoT management service |
| `filebeat` | `docker.elastic.co/beats/filebeat:8.13.4` | Ships JSON logs to analysis host |
| `collector` (optional) | built from `./collector` | Local spool/buffer if analysis host is down |

Actual resource usage has not been measured. Run `scripts/research/measure-pi.sh`
on the Pi under a documented workload; preserve the resulting CSV with hardware,
software, and campaign context. Compose limits are configuration ceilings, not
measured consumption.

## Setup (one time)

```bash
ssh user@PI_IP
cd ~/iot-honeypot-ids/pi
cp .env.example .env
# edit .env — at minimum set CENTRAL_SERVER_IP
./scripts/configure.sh     # sanity-checks env + docker availability
```

## Day-to-day operations

```bash
./scripts/start.sh         # docker compose up -d
./scripts/stop.sh          # docker compose down
./scripts/restart.sh
./scripts/status.sh        # per-container CPU/RAM/health/uptime
./scripts/logs.sh [svc]    # tail logs (optionally one service)
./scripts/update.sh        # git pull + docker compose build + restart
```

All scripts are thin wrappers around `docker compose` so they remain
understandable. PowerShell equivalents (`.ps1`) are provided for parity with
the Windows-side tooling on PC1.

## Honeypots

### 1. Cowrie (SSH / Telnet)

- Config: [`honeypots/cowrie/cowrie.cfg`](honeypots/cowrie/cowrie.cfg)
- Fake filesystem / hostname / `etc` populated to look like a cheap IoT
  embedded Linux device.
- JSON logs are written to `/var/log/cowrie/cowrie.json` inside the container
  and bind-mounted to `./honeypots/cowrie/var/log/cowrie/` on the Pi.
- Filebeat tails this file and ships it to PC1 Logstash.

### 2. Camera HTTP honeypot

- Code: [`honeypots/camera/`](honeypots/camera/)
- Endpoints mimic a cheap IP camera / DVR: `/`, `/login`, `/admin`,
  `/config`, `/system`, `/status`, `/network`, `/users`, `/device`,
  `/firmware`, `/snapshot`, `/video`, `/api/`.
- Records every request as a structured JSON event (method, URI, status,
  user-agent, headers, payload metadata, session id).
- Built on Python + Flask for tiny image size and easy audit.

### 3. IoT service

- Code: [`honeypots/iot-service/`](honeypots/iot-service/)
- A minimal TCP service that pretends to be a small IoT management daemon.
- Captures banner-grabs, malformed payloads, and "command" attempts.
- Uses a small state machine to look believable without actually executing
  anything.

## Telemetry forwarding

```
honeypot container
   → JSON log file (bind mount)
   → Filebeat container (tails the file)
   → PC1 Logstash (TCP 5044)
   → Elasticsearch
```

If PC1 is unreachable, Filebeat keeps events in its local spool on the Pi and
retries — telemetry is not silently lost.

## Resource limits

Per-container limits are declared explicitly in
[`docker-compose.yml`](docker-compose.yml) so the Pi stays usable under
attack. Run `./scripts/status.sh` to see live usage.

## Security

- Honeypots run on an isolated Docker network (`honeynet`).
- The real Pi OS is never mounted into a honeypot container.
- `/var/run/docker.sock` is **never** exposed to attacker-facing containers.
- Cowrie runs as a non-root user inside the container.
- Read-only root filesystems where practical; small tmpfs mounts for state.
- `--privileged` is never used.

See [`../docs/security/safety.md`](../docs/security/safety.md) for the full
hardening checklist.

## Offline development

If you do not have a Pi available, you can still develop the PC1 side by
importing synthetic sample data:

```bash
cd ~/iot-honeypot-ids
./scripts/dev/import-sample-data.sh
```

The sample data is clearly labeled `SYNTHETIC` and is never confused with
live telemetry in dashboards (it carries `event.kind: synthetic`).
