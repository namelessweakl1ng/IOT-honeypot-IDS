# Fedora/Linux laptop and Raspberry Pi setup

## Laptop

Install current Docker Engine/Compose, Git, Python 3.12+, and Node.js. Clone the repository, copy `.env.example` to `.env`, and replace the example network values. Place the dedicated Pi private key at `secrets/pi_ssh_key` with mode `0600` (or set `PI_SSH_KEY_PATH`). Capture the Pi host key with `ssh-keyscan -H "$PI_HOST" > secrets/known_hosts`, then compare `ssh-keygen -lf secrets/known_hosts` against a fingerprint obtained directly from the Pi console before trusting it. Set mode `0600` or stricter on that file too. Compose mounts both host files read-only into a root-only staging path. The backend entrypoint copies them with ownership UID 10001 and mode `0600`, verifies readability as that user, then drops privileges before starting FastAPI. SSH uses this dedicated file with `StrictHostKeyChecking=yes`; it never silently trusts a changed key. `secrets/` is ignored by Git. Run `./scripts/analysis-up.sh`. Confirm `docker compose ps`, `curl http://localhost:8000/health`, and Kibana status. Install Python requirements and frontend packages before local tests.

## Raspberry Pi

Use 64-bit Raspberry Pi OS with Docker Engine/Compose. Copy `sensor/` to `/opt/trapsig/sensor`, copy its environment example, and set `ANALYSIS_HOST`, `SENSOR_ID`, and hostname. Permit Pi-to-laptop TCP 5044 and lab-to-Pi decoy ports only. Run `setup.sh`, `start.sh`, then `status.sh`.

Create an unprivileged `trapsig` SSH account. Restrict its authorized key to `manage.sh`; do not grant an interactive shell or arbitrary sudo. Set laptop `PI_HOST`, `PI_USER`, and the mounted private-key path. Do not commit keys.

Physical reachability, ARM image compatibility, sustained resource use, and end-to-end telemetry delivery require the actual lab and are **NOT MEASURED** here.
