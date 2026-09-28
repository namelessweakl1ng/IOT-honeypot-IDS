# TRAPSIG

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

## Repository map

| Path | Responsibility |
| --- | --- |
| `frontend/` | Small Next.js operational and experiment UI |
| `backend/` | Sole domain API, sessionization, rules, correlation, Pi actions |
| `elk/` | Logstash normalization, Elasticsearch and Kibana configuration |
| `sensor/` | Hardened Pi honeypots, Filebeat and management scripts |
| `attacks/` | Subnet-restricted controlled scenario runner and manifests |
| `tests/` | Behavior tests and clearly synthetic fixtures |
| `docs/` | Five authoritative project guides |

## Start the laptop

```bash
cp .env.example .env
docker compose up -d
docker compose ps
```

Open TRAPSIG at `http://localhost:3000`, the API at `http://localhost:8000/docs`, and Kibana at `http://localhost:5601`.

## Start the Raspberry Pi

```bash
cd sensor
cp .env.example .env        # set ANALYSIS_HOST to the laptop
./scripts/setup.sh
./scripts/start.sh
./scripts/status.sh
```

Install the backend SSH public key for the dedicated, restricted Pi user. The API invokes only `/opt/trapsig/sensor/scripts/manage.sh <start|stop|restart> <known-service>`.

## Run a controlled scenario

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r attacks/requirements.txt
export LAB_SUBNET=192.168.50.0/24 HONEYPOT_IP=192.168.50.10
python -m attacks.runner.run multi-honeypot-attack --target "$HONEYPOT_IP"
```

The explicit target must be a usable private address inside `LAB_SUBNET`. Scenarios never scan ranges, persist, create C2, or exfiltrate data.

## Create an experiment

Create it with `POST /experiments`, start it with `POST /experiments/{id}/start`, run the matching controlled scenario, then finish it with `POST /experiments/{id}/finish`. Finishing correlates immutable events by time window, attacker IP, and target IP and records linked session/detection IDs plus TP/FN outcome.

## Test and validate

```bash
pip install -r backend/requirements.txt -r attacks/requirements.txt ruff
cd frontend && bun install && cd ..
./scripts/test.sh
./scripts/validate.sh
```

See [setup](docs/SETUP.md), [architecture](docs/ARCHITECTURE.md), [event schema](docs/EVENT_SCHEMA.md), [experiment method](docs/EXPERIMENTS.md), and [demonstration](docs/DEMO.md).

## Safety

Run only on an isolated private lab network you own. Do not expose deception services to the Internet. Honeypots return static responses and provide no real device or shell capability. Keep the Pi management key out of Git and restrict it to the management script. Physical-Pi resource, ingestion, and detection measurements are currently **NOT MEASURED**.
