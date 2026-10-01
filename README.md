# TRAPSIG

[![TRAPSIG CI](https://github.com/namelessweakl1ng/IOT-honeypot-IDS/actions/workflows/ci.yml/badge.svg)](https://github.com/namelessweakl1ng/IOT-honeypot-IDS/actions/workflows/ci.yml)

TRAPSIG is a multi-honeypot IoT cybersecurity experimentation and attack-analysis platform. A Raspberry Pi exposes deliberately limited deception services; Filebeat forwards their logs to a laptop where Logstash normalizes telemetry, Elasticsearch stores it, FastAPI reconstructs sessions and explains rule detections, and Next.js provides experiment-oriented control. Kibana remains the deep-analysis interface.

## Why it exists

The project provides a reproducible, understandable laboratory for studying how activity crosses IoT services and how deterministic detections behave. It is a final-year research platform, **not** a production SIEM and not a safe target on the public Internet.

## Two-machine architecture

```text
controlled attacker -> Raspberry Pi: Cowrie SSH/Telnet, camera HTTP,
                       IoT TCP, MQTT, router HTTP + Filebeat
                    -> Laptop: Logstash -> Elasticsearch -> Kibana
                                             |-> FastAPI -> Next.js
```

Addresses are never encoded in application code. Configure the laptop/Pi/attacker subnet in environment files. Elasticsearch is the only telemetry and derived-data store. Raw `trapsig-events-*` documents are immutable; experiments reference their IDs.

FastAPI continuously performs one deliberately small, idempotent processing cycle: it reads normalized events, deterministically reconstructs source-IP sessions, upserts `trapsig-sessions`, evaluates explainable rules, and upserts `trapsig-detections`. Stable IDs make restart and repeated cycles safe without marking or mutating raw events.

## Repository map

| Path | Responsibility |
| --- | --- |
| `frontend/` | Small Next.js operational and experiment UI |
| `backend/` | Sole domain API, sessionization, rules, correlation, Pi actions |
| `elk/` | Logstash normalization, Elasticsearch and Kibana configuration |
| `sensor/` | Hardened Pi honeypots, Filebeat and management scripts |
| `attacks/` | Subnet-restricted controlled scenario runner and manifests |
| `tests/` | Behavior tests and clearly synthetic fixtures |
| `docs/` | Authoritative architecture, persona, experiment, validation, and research guides |

## Start the laptop

```bash
cp .env.example .env
mkdir -p secrets && install -m 600 ~/.ssh/trapsig_pi secrets/pi_ssh_key
set -a; . ./.env; set +a
ssh-keyscan -H "$PI_HOST" > secrets/known_hosts
ssh-keygen -lf secrets/known_hosts  # compare this fingerprint with the Pi console
chmod 600 secrets/known_hosts
./scripts/preflight.sh
docker compose up -d --build
docker compose ps
```

Open TRAPSIG at `http://localhost:3000`, the API at `http://localhost:8000/docs`, and Kibana at `http://localhost:5601`.

## Start the Raspberry Pi

```bash
cd sensor
cp .env.example .env        # set ANALYSIS_HOST to the laptop
./scripts/setup.sh          # validates environment and Compose first
./scripts/start.sh
./scripts/status.sh
```

Install the backend SSH public key for the dedicated, restricted Pi user using the forced-command `authorized_keys` entry in [the setup guide](docs/SETUP.md). Verify the scanned host-key fingerprint from the Pi itself before starting Compose; `ssh-keyscan` alone does not authenticate the host. The backend startup copies the host-owned, mode-0600 key and known-hosts file into its private container SSH directory, assigns them to UID 10001, and then drops privileges. SSH enforces the dedicated known-hosts file with strict checking. The API invokes only `/opt/trapsig/sensor/scripts/manage.sh <start|stop|restart> <known-service>` (plus its argument-free status operation).

## Run a controlled scenario

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r attacks/requirements.txt
export LAB_SUBNET=192.168.50.0/24 HONEYPOT_IP=192.168.50.10
python -m attacks.runner.run multi-honeypot-attack --target "$HONEYPOT_IP"
```

The explicit target must be a usable private address inside `LAB_SUBNET`. Scenarios never scan ranges, persist, create C2, or exfiltrate data.

## Create an experiment

Create it with `POST /experiments`, start it with `POST /experiments/{id}/start`, run the matching controlled scenario, then finish it with `POST /experiments/{id}/finish`. Finishing correlates immutable events by time window, attacker IP, and target IP and records linked session/detection IDs plus a TP/FN/TN/FP/INCONCLUSIVE evaluation result.

## Test and validate

```bash
pip install -r backend/requirements.txt
pip install -r attacks/requirements.txt
pip install -r requirements-dev.txt
cd frontend && npm ci && cd ..
./scripts/test.sh
./scripts/validate.sh
```

`test.sh` runs Ruff, the complete Python suite, frontend linting, and TypeScript
checking. `validate.sh` additionally validates both committed Compose files,
checks shell syntax, and performs the frontend production build. GitHub pull
requests automatically run these unit/static checks plus project image builds
and real Elasticsearch, template-setup, Logstash-pipeline, and backend API smoke
checks.

The Docker integration check does not exercise the physical Filebeat-to-Logstash
path, a Fedora laptop, or Raspberry Pi behavior. Those remain separate lab
verification steps; green GitHub CI does not establish hardware behavior or
physical resource usage.

See the [persona/fidelity matrix](docs/PERSONAS.md), [research traceability](docs/RESEARCH_TRACEABILITY.md), [final validation checklist](docs/FINAL_VALIDATION.md), [research evaluation](docs/EVALUATION.md), [setup](docs/SETUP.md), [architecture](docs/ARCHITECTURE.md), [event schema](docs/EVENT_SCHEMA.md), [experiment method](docs/EXPERIMENTS.md), and [demonstration](docs/DEMO.md).

## Safety

Run only on an isolated private lab network you own. Do not expose deception services to the Internet. The five honeypots provide six logical services: Cowrie SSH/Telnet, camera HTTP, router HTTP, IoT TCP, and MQTT. They provide bounded synthetic device/protocol emulation and never expose real device control, host shells, routing, persistent broker behavior, or arbitrary execution. Keep the Pi management key out of Git and restrict it to the management script. Physical-Pi resource, ingestion, and detection measurements are currently **NOT MEASURED**.
