# TRAPSIG college demonstration

This procedure demonstrates one controlled SSH brute-force campaign against the project's Cowrie honeypot. It is written for an evaluator with basic networking/security knowledge. It requires the three isolated lab machines and has **not** been physically run in this workspace.

## Architecture and evidence categories

```text
Attacker action -> Raspberry Pi Cowrie -> JSON event -> Filebeat -> Logstash
     -> Elasticsearch -> FastAPI session/campaign/features/detection -> root Next.js dashboard
```

The Pi is the sensor, the Fedora analysis host runs ELK and FastAPI, and the attacker/test host generates a bounded scenario. `SYNTHETIC` demo fixtures, `PUBLIC_DATASET` IoT-23 flows, `CONTROLLED_LAB` scenario ground truth, and observed `LIVE_TELEMETRY` are separate categories. Detector predictions are never treated as ground truth. Only one IDS-domain API is authoritative: nested FastAPI. The production dashboard is the root Next.js application.

## Prerequisites

- Three hosts on an isolated lab network with explicit routes and firewall rules.
- Fedora analysis host: Docker Engine/Compose, Python 3.11 compatible with the API image, and Bun/Node for the root UI.
- Raspberry Pi: Docker Engine/Compose; the Pi compose builds the local camera and IoT service images.
- Attacker host: Bash, Python 3, `sshpass`, and a clone of this repository.
- Unique local credentials in ignored `.env` files. Do not use the template strings as credentials.
- The attacker target must be inside the configured `LAB_SUBNET`; the scenario runner enforces that boundary.

The Compose file configures Elasticsearch, Logstash, Kibana, and Filebeat as Elastic Stack **8.13.4** by default (`ELK_VERSION` can override the default). The FastAPI container base is Python **3.11-slim-bookworm**. Root package dependencies are constrained by `package.json` and `bun.lock`; the repository does not pin a Bun runtime version. Use `bun --version` and record it with the demonstration evidence.

## Five-terminal layout

1. **Terminal 1 — Fedora analysis host, services:** start ELK/API and retain service logs.
2. **Terminal 2 — Fedora analysis host, preflight/mode/queries:** health checks, set LIVE, correlate records, and record IDs.
3. **Terminal 3 — Pi SSH:** configure/start Cowrie and Filebeat; inspect logs.
4. **Terminal 4 — attacker host:** run only `ssh-bruteforce` against the Pi.
5. **Terminal 5 — Fedora analysis host, dashboard:** start the root UI and show the same event/session/detection lineage.

## Startup and preflight

### Terminal 1: analysis services

From the repository checkout on Fedora:

```bash
cd iot-honeypot-ids
./scripts/setup/init.sh
```

Setup creates ignored environment files and installs the Python API dependencies; it does not create research data. Replace every template credential with a unique local secret, set Pi/attacker addresses and `LAB_SUBNET`, then start the stack:

```bash
./scripts/deployment/start-pc1.sh
```

Expected: compose lists healthy services and Elasticsearch bootstrap completes. A failure means fix Docker, environment, disk/memory, or image health before proceeding.

### Terminal 2: check services and explicitly enter LIVE

From the nested project root, source the dashboard environment and run preflight:

```bash
cd iot-honeypot-ids
set -a
source dashboard/.env
set +a
export ANALYSIS_HOST="<analysis_host_ip>"
export PI_IP="<pi_ip>"
./scripts/testing/preflight-lab.sh
```

Expected: each reachable command/port/service is marked `PASS`; unconfigured checks are `SKIPPED`; an expected but unreachable service is `FAIL`. Do not proceed on a required `FAIL`.

Check service health and Logstash's Beats listener directly:

```bash
curl --fail http://127.0.0.1:8000/health
curl --fail --user "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200/_cluster/health
ss -ltn | grep ':5044'
```

Expected: API health JSON, Elasticsearch `green` or `yellow`, and a TCP listener on 5044. Failure is infrastructure unavailability, not zero detections.

Explicitly enter LIVE mode (the API key is required):

```bash
curl --fail -X POST -H "X-API-Key: ${API_SECRET_KEY}" http://127.0.0.1:8000/mode/live
```

Expected: response confirms `LIVE`. A rejected request means check the API key and current mode; do not locally label the UI LIVE without API confirmation.

### Terminal 3: Raspberry Pi sensor

SSH to the Pi and from its repository checkout:

```bash
cd iot-honeypot-ids/pi
./scripts/configure.sh
./scripts/start.sh
./scripts/status.sh
docker compose ps
docker compose logs --tail=50 filebeat
```

Set `CENTRAL_SERVER_IP` in the Pi's ignored `pi/.env` to the analysis host. Expected: Cowrie and Filebeat containers running, Filebeat connected to Logstash. A warning means check host routing/firewall, port 5044, and Filebeat output configuration.

### Terminal 4: one controlled attack

On the attacker host, configure `attacker/.env` with the Pi address, the lab subnet, and the Cowrie SSH port. From that host's clone:

```bash
cd iot-honeypot-ids/attacker
./run-scenario.sh --target "<pi_ip>" --scenario ssh-bruteforce
```

This performs the bounded synthetic credential attempts described by the scenario and prints attacker-side `campaign_id`, `run_id`, and a path to its run summary. Expected: summary written under `attacker/runs/`. The run's campaign identifier is scenario metadata; the backend campaign correlator may create a different ID. Keep both IDs distinct in notes. Never disable the `LAB_SUBNET` check.

## Follow the live trace

### Terminal 2: event, session, campaign, features, detector

Inspect newly indexed events and identify the event/session IDs:

```bash
curl --fail 'http://127.0.0.1:8000/events?size=20'
```

Expected: event JSON includes nonempty `event_id`, `session_id`, timestamp, source, device, honeypot, and event type. No result means inspect Filebeat, Logstash, and Elasticsearch before continuing.

If the session scheduler has not materialized it yet, request bounded materialization and correlation:

```bash
curl --fail -X POST -H "X-API-Key: ${API_SECRET_KEY}" 'http://127.0.0.1:8000/sessions/materialize?lookback_minutes=60'
curl --fail -X POST -H "X-API-Key: ${API_SECRET_KEY}" 'http://127.0.0.1:8000/campaigns/correlate?lookback_minutes=240'
curl --fail 'http://127.0.0.1:8000/sessions?size=20'
curl --fail 'http://127.0.0.1:8000/campaigns?size=20'
```

Expected: a session references the observed event ID; a backend campaign contains that session ID. The attacker-side campaign tag and backend campaign ID are separate unless telemetry explicitly links them.

Copy the returned IDs into these commands:

```bash
./scripts/testing/show-campaign.sh <campaign_id>
./scripts/testing/show-session.sh <session_id>
curl --fail 'http://127.0.0.1:8000/features/<session_id>'
curl --fail -X POST -H "X-API-Key: ${API_SECRET_KEY}" 'http://127.0.0.1:8000/detect/hybrid/<session_id>'
curl --fail 'http://127.0.0.1:8000/detections?session_id=<session_id>'
./scripts/testing/show-detection.sh <detection_id>
```

Expected features include a session ID, feature schema version, and measured feature object. If no hybrid signal fires, report **NO SIGNAL**; that is not proof the session was benign. For this selected SSH credential scenario, the rule detector is expected to contribute when telemetry contains the configured authentication-failure evidence. A persisted detection contains detector version, prediction, contributed signals, explanation, and lineage. Do not substitute a fixture when a live step fails.

Record the attack scenario as `ground_truth_label=ssh-bruteforce` and `ground_truth_source=SCENARIO_GROUND_TRUTH` from the attacker run summary. Record the detector's `label` separately as a prediction. The controlled scenario label describes the action run, not proof every expected event reached Elasticsearch.

### Terminal 5: dashboard walkthrough

From the outer repository root, configure the UI to reach the same analysis API:

```bash
cd <repository_root>
set -a
source iot-honeypot-ids/dashboard/.env
set +a
export TRAPSIG_BACKEND_API_KEY="$API_SECRET_KEY"
export FASTAPI_URL=http://127.0.0.1:8000
bun run dev
```

Open `http://<analysis_host_ip>:3000`. Show Overview, Events, Sessions, Detections, and detection lineage. Point out the event ID in the session timeline, backend campaign ID, detector/version, contributed signal, prediction, and reason. The mode must be `LIVE`. `BACKEND UNAVAILABLE` means the service path failed; `NO LIVE TELEMETRY` means the configured live query returned no events. Neither means “zero attacks” without a defined query and time window.

## Cleanup

Stop the Pi honeypot services:

```bash
cd iot-honeypot-ids/pi
./scripts/stop.sh
```

Stop the ELK/API stack on Fedora after retaining approved evidence:

```bash
cd iot-honeypot-ids/dashboard
docker compose down
```

Keep `.env` files and run summaries local according to lab policy. Never commit passwords, raw packet captures, or unreviewed attacker logs.

## Troubleshooting

- **Preflight `FAIL`:** repair the named host/port/service before an attack; missing host configuration is shown as `SKIPPED`.
- **Pi cannot reach port 5044:** check routes/firewall on both hosts, Logstash's Beats listener, and the configured Pi `CENTRAL_SERVER_IP`.
- **Filebeat connected but no event:** inspect `docker compose logs --tail=100 filebeat` on the Pi and `docker compose logs --tail=100 logstash` on Fedora.
- **Event but no session:** inspect `/sessions/scheduler/status`, then request the bounded materialization endpoint.
- **Session but no campaign:** run the correlation endpoint and verify source-IP/time grouping; never equate the attacker run tag with backend correlation ID.
- **Feature extraction 404:** verify the session contains events, then inspect API logs.
- **No detection:** show the detector response and its evidence honestly. Absence of a detection is not a benign label.
- **Dashboard says `BACKEND UNAVAILABLE`:** check API health and `FASTAPI_URL`; do not switch to synthetic fixtures and call it LIVE.

IoT-23 preparation and experiments are a separate offline public-dataset workflow documented in `iot-honeypot-ids/research/datasets/iot23/README.md`. It is not part of this physical demonstration.
