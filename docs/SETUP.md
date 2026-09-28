# Fedora/Linux laptop and Raspberry Pi setup

## Laptop

Install current Docker Engine/Compose, Git, Python 3.12+, and Bun. Clone the repository, copy `.env.example` to `.env`, replace the example secret and network values, and run `./scripts/analysis-up.sh`. Confirm `docker compose ps`, `curl http://localhost:8000/health`, and Kibana status. Install Python requirements and frontend packages before local tests.

## Raspberry Pi

Use 64-bit Raspberry Pi OS with Docker Engine/Compose. Copy `sensor/` to `/opt/trapsig/sensor`, copy its environment example, and set `ANALYSIS_HOST`, `SENSOR_ID`, and hostname. Permit Pi-to-laptop TCP 5044 and lab-to-Pi decoy ports only. Run `setup.sh`, `start.sh`, then `status.sh`.

Create an unprivileged `trapsig` SSH account. Restrict its authorized key to `manage.sh`; do not grant an interactive shell or arbitrary sudo. Set laptop `PI_HOST`, `PI_USER`, and the mounted private-key path. Do not commit keys.

Physical reachability, ARM image compatibility, sustained resource use, and end-to-end telemetry delivery require the actual lab and are **NOT MEASURED** here.
