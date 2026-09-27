# TRAPSIG demonstration

This is the single operator sequence for the frozen project. The dashboard is the root Next.js app; the runtime/research implementation is `iot-honeypot-ids/`. This procedure demonstrates controlled telemetry only when the three lab machines and services are available. The steps have not been physically run here.

## Machines and modes

1. **Analysis host (Linux):** ELK, FastAPI, and root Next.js UI. It receives telemetry and owns runtime detections.
2. **Raspberry Pi:** Cowrie, camera, IoT honeypots, and Filebeat. It is a sensor, not the ML host.
3. **Attacker host:** runs the bounded, configured scenario against the isolated Pi.

Use `LIVE` only with a reachable backend. Synthetic sample import is a labeled developer fixture, not physical evidence. The optional public-data section is the separate IoT-23 benchmark. IoT-23 network flows are not Pi honeypot events.

## Primary controlled campaign

### 1. Start the analysis host

From the repository root on the analysis host:

```bash
cd iot-honeypot-ids
./scripts/setup/init.sh
```

Configure the generated `dashboard/.env` with unique lab-only credentials and the host's reachable interface address. Keep `.env` local and never commit it.

### 2. Start ELK and FastAPI

```bash
./scripts/deployment/start-pc1.sh
```

Expected: compose services start and the script reports Kibana and API URLs. Failure means Docker, environment configuration, or service health must be resolved before continuing.

### 3. Verify health and ingestion listener

```bash
curl --fail http://127.0.0.1:8000/health
curl --fail -u "elastic:${ELASTIC_PASSWORD}" http://127.0.0.1:9200/_cluster/health
ss -ltn | grep ':5044'
```

Expected: API health JSON, Elasticsearch cluster health JSON, and a listener on TCP 5044. An unreachable dependency is a stop condition, not zero detections.

Load the configured local API secret and explicitly enter LIVE mode so the session and detection endpoints are enabled:

```bash
set -a
source dashboard/.env
set +a
curl --fail -X POST -H "X-API-Key: ${API_SECRET_KEY}" http://127.0.0.1:8000/mode/live
```

Expected: JSON confirms `LIVE`. Configure unique hexadecimal lab secrets so the shell-compatible env file can be sourced safely.

### 4. Start the Raspberry Pi honeypots and verify Filebeat

On the Pi, with its configured copy of the repository:

```bash
cd ~/iot-honeypot-ids/pi
./scripts/configure.sh
./scripts/start.sh
./scripts/status.sh
docker compose ps
docker compose logs --tail=50 filebeat
```

Expected: configured containers are running and Filebeat has no connection/authentication error to the analysis host. Confirm TCP 5044 from the Pi using an available `nc -vz <ANALYSIS_HOST_IP> 5044` command. Failure means check host firewall, routing, Logstash, and Filebeat output configuration.

### 5. Run controlled reconnaissance and record its campaign ID

On the attacker host, set the isolated lab subnet and Pi address in `attacker/.env` (copy `.env.example` first if needed), then run:

```bash
cd iot-honeypot-ids/attacker
./run-scenario.sh --target <PI_IP> --scenario camera-recon
```

Expected: bounded requests and a final run summary with generated campaign and run identifiers. Record both. The runner identifier is campaign ground-truth metadata; the backend correlator may assign a separate campaign ID from observed sessions. Link those records using the session/source and actual API responses; do not assume the identifiers are identical. The runner must reject targets outside `LAB_SUBNET`; never disable that check.

### 6. Query the event, session, and detection

Back on the analysis host, allow the configured ingestion/reconstruction interval, then query:

```bash
curl --fail 'http://127.0.0.1:8000/events?size=20'
curl --fail 'http://127.0.0.1:8000/sessions?size=20'
curl --fail 'http://127.0.0.1:8000/campaigns?size=20'
curl --fail 'http://127.0.0.1:8000/detections?size=20'
curl --fail -X POST -H "X-API-Key: ${API_SECRET_KEY}" 'http://127.0.0.1:8000/sessions/materialize?lookback_minutes=60'
curl --fail 'http://127.0.0.1:8000/sessions?size=20'
curl --fail -X POST -H "X-API-Key: ${API_SECRET_KEY}" 'http://127.0.0.1:8000/detect/hybrid/<SESSION_ID>'
curl --fail 'http://127.0.0.1:8000/detections?session_id=<SESSION_ID>'
```

Replace `<SESSION_ID>` with the ID from the session response. Expected output shapes are JSON collections/details; dynamic event, session, and detection IDs vary. Check returned records for their actual campaign identifiers and confirm the session/event lineage. The runner campaign identifier is not automatically propagated into the backend correlator identity. A detector response saying no signal fired is a valid outcome. If event exists but session/detection does not, inspect scheduler status, session detail, and API logs rather than inventing a result.

### 7. Open dashboard and show lineage

In a separate analysis-host terminal, launch the root dashboard using the same secret and API address:

```bash
cd <REPOSITORY_ROOT>
set -a
source iot-honeypot-ids/dashboard/.env
set +a
export TRAPSIG_BACKEND_API_KEY="$API_SECRET_KEY"
export FASTAPI_URL=http://127.0.0.1:8000
bun run dev
```

Open `http://<ANALYSIS_HOST_IP>:3000`, then open Events, Sessions, Detections, and the detection lineage detail. Show campaign -> event -> session -> features -> detector/version -> prediction/reason. The actual IDs and prediction are runtime-dependent; absence of a detection is a valid observation and must not be replaced with demo data.

### 8. Optional public-dataset experiment

IoT-23 download is about 8.7 GB for the small flow archive. From a separate analysis checkout:

```bash
cd iot-honeypot-ids
export IOT23_DATA_DIR="$HOME/datasets/iot23"
./scripts/research/prepare-iot23.sh --download
cat research/datasets/iot23/manifest.json
cat research/datasets/iot23/summary.md
./scripts/research/run-iot23-experiment.sh \
  --dataset "$PWD/research/datasets/iot23/prepared/normalized/flows.jsonl" \
  --experiment-id iot23-lr-seed42 \
  --seed 42 \
  --algorithm logistic_regression \
  --feature-version iot23-flow-v1 \
  --split-protocol scenario
ls research/experiments/iot23/iot23-lr-seed42
```

Preparation fails clearly when data are absent or malformed. A local computed archive checksum is not an authenticity check unless compared with an independently trusted digest. The runner fits on train scenarios, reports validation descriptively, and evaluates the disjoint test scenarios once. Its deterministic per-scenario reservoir cap defaults to 10,000 flows to bound memory; the manifest records seen/retained counts. Outputs include the split, model artifact, metrics, confusion matrices, predictions, environment, and README. No benchmark scores are supplied by this demo procedure.

### 9. Clean up

On the attacker host, preserve the run summary as research evidence and remove any local credentials according to lab policy. On the Pi:

```bash
cd ~/iot-honeypot-ids/pi
./scripts/stop.sh
```

On the analysis host, stop only after retaining approved logs/artifacts:

```bash
cd iot-honeypot-ids/dashboard
docker compose down
```

## Troubleshooting

- **Pi cannot reach analysis host:** verify routes and firewall; `ping <ANALYSIS_HOST_IP>` and `nc -vz <ANALYSIS_HOST_IP> 5044`.
- **TCP 5044 unavailable:** `ss -ltnp | grep ':5044'`; inspect `docker compose ps` and Logstash logs.
- **Filebeat unhealthy:** `docker compose logs --tail=100 filebeat`; verify mounted log paths and output host/credentials.
- **Elasticsearch / Logstash unhealthy:** `docker compose ps` and `docker compose logs --tail=100 elasticsearch logstash`.
- **No events:** inspect Pi honeypot logs, Filebeat registry/output logs, Logstash dead-letter routing, then Elasticsearch index health.
- **No session:** query raw events and `/sessions/scheduler/status`; check required event/session IDs and scheduler/API logs.
- **No detection:** query session detail, then detector endpoint and model/rule status; no detection is not proof of benign behavior.
- **Dashboard empty or BACKEND UNAVAILABLE:** check API health and root app `FASTAPI_URL` configuration. Do not switch to synthetic data and call it LIVE.
- **Missing IoT-23:** set `IOT23_DATA_DIR` to extracted data; the preparation command has no synthetic fallback.
- **Invalid model:** inspect its dataset provenance, feature version, and registry status. Synthetic-trained models are not research-active.
