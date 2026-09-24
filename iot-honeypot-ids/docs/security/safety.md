# Security & safety

## Threat model summary

This platform is a **defensive research lab**. It detects and classifies
behavioral patterns observed against intentionally vulnerable honeypots. It
does **not** detect zero-day vulnerabilities, attacks against the real Pi
host, or attacks against systems outside the lab. See
[`shared/documentation/threat-model.md`](../../shared/documentation/threat-model.md).

## Container hardening checklist

Every honeypot container in `pi/docker-compose.yml` is configured with:

- [x] `cap_drop: ALL` — no capabilities
- [x] `security_opt: no-new-privileges:true`
- [x] `read_only: true` filesystem where practical
- [x] `tmpfs` for the few writable paths (`/tmp`, log dirs)
- [x] `mem_limit` and `cpus` set per-container
- [x] `pids_limit` set to prevent fork bombs
- [x] Non-root `user: <uid>:<gid>` for camera + iot-service
- [x] `restart: unless-stopped` policy
- [x] `init: true` to reap zombie processes (Cowrie)
- [x] `healthcheck` so Docker knows when to restart
- [x] Log rotation (`max-size` + `max-file`)
- [x] Isolated `honeynet` Docker network
- [x] `/var/run/docker.sock` is **never** bind-mounted
- [x] `--privileged` is **never** used

## Attacker safety checklist

Every attacker script (`attacker/run-scenario.sh`):

- [x] Requires `--target <ip>` (no default)
- [x] Refuses targets not in `LAB_SUBNET`
- [x] Refuses loopback / link-local / multicast / unspecified IPs
- [x] Targets only the configured honeypot ports
- [x] Does not perform broad network sweeps
- [x] Does not establish persistence
- [x] Does not exfiltrate credentials out of the repo
- [x] Does not deploy command-and-control
- [x] Refuses scenarios with severity > `MAX_SEVERITY`

## API safety checklist

The FastAPI service (`dashboard/api`):

- [x] `/health` is always open (Docker healthcheck needs it)
- [x] Every other endpoint requires the client IP to be in `API_ALLOWED_CIDRS`
- [x] `POST /replay` re-validates the target IP against the lab subnet (defense-in-depth — the attacker runner also enforces this)
- [x] `POST /training` invokes the model-lab CLI via `subprocess.run` with a fixed argument list (no shell=True, no string interpolation of user input)
- [x] CORS is permissive in dev but should be locked down for production
- [x] Secrets come from env vars (`ELASTIC_PASSWORD`, `API_SECRET_KEY`), never from source

## Elasticsearch safety

- [x] ES is bound to `0.0.0.0` but exposed on the host port — protect with a host firewall
- [x] `xpack.security.enabled: true` — auth required
- [x] Default `elastic` password must be changed in `.env` before deployment
- [x] `xpack.ml.enabled: false` — we don't need ES's built-in ML (we have our own)
- [x] `xpack.monitoring.enabled: false` — we don't phone home

## Logstash safety

- [x] Beats input on port 5044 is bound to `0.0.0.0` — protect with a host firewall so only the Pi can reach it
- [x] No management API exposed externally

## Kibana safety

- [x] Requires login (`elastic` user)
- [x] Bound to lab subnet only via host firewall

## PCAP safety (optional)

If `ENABLE_PCAP=true` on the Pi:

- [x] PCAP files rotate hourly
- [x] Old PCAPs deleted after `PCAP_RETENTION_HOURS` (default 24)
- [x] PCAPs are never shipped off the Pi (they stay on the SD card)
- [x] PCAPs are in `.gitignore` so they never get committed

## What to do if an attacker escapes a honeypot

The honeypots are designed so an attacker *should* be contained. If you
suspect escape:

1. `docker compose down` on the Pi immediately
2. Inspect the honeypot's container logs for suspicious activity
3. Check the Pi host for unexpected processes: `ps aux | grep -v 'docker\|sshd\|systemd'`
4. Check for unexpected network connections: `ss -tnp`
5. If anything is suspicious, reflash the Pi SD card from a known-good image
6. Rotate any credentials that may have been on the Pi (none should be — the Pi only has telemetry-forwarding creds)

## What to do if the lab is compromised

If PC1 is compromised (someone got into ES or the API):

1. `docker compose down` on PC1
2. Rotate the `ELASTIC_PASSWORD` and `API_SECRET_KEY` in `.env`
3. Wipe the ES data volume: `docker volume rm iot-honeypot-dashboard_es_data`
4. Restart: `docker compose up -d`
5. Investigate logs in `dashboard/logs/`

## Operational hygiene

- Never commit `.env` (it's in `.gitignore`)
- Never commit PCAP files
- Never commit trained models > 100 MB (also in `.gitignore`)
- Rotate the `elastic` password periodically
- Keep the Pi OS updated: `sudo apt update && sudo apt upgrade`
- Keep Docker updated on all machines
