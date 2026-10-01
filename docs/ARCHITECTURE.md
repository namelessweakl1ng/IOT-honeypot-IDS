# Architecture

There are two hosts. The Pi runs five containers representing six logical services (Cowrie supplies SSH and Telnet) plus Filebeat. Filebeat's disk queue is the sole edge buffer and sends JSON/JSONL over Beats to laptop Logstash. Per-family filters normalize records into the canonical schema; malformed records go to `trapsig-dead-letter-*`, never silently disappear.

Elasticsearch owns date-based `trapsig-events-*` raw indices and the three stable derived indices `trapsig-sessions`, `trapsig-detections`, and `trapsig-experiments`. FastAPI is the only domain backend. Its focused routers query Elasticsearch, while services deterministically reconstruct source-IP sessions, apply explainable rules, correlate experiments, and invoke a fixed Pi management script through SSH. Next.js contains only presentation and a typed HTTP client. Kibana directly explores Elasticsearch for detailed research analysis.

The deployment deliberately has only the components in this document; no parallel messaging, storage, API, collector, runtime-mode, or model lifecycle exists.

## Custom honeypot runtime

The camera, router, IoT TCP service, and MQTT decoys use a small shared socket runtime. It owns bounded connection lifecycle and JSONL persistence, assembles size-limited HTTP requests across reads, reads one bounded IoT line, and assembles one bounded MQTT frame using Remaining Length. Separate persona modules own parsing and replies. Camera and router are stateful bounded HTTP personas with expiring in-memory sessions; IoT is a bounded line protocol; MQTT is a bounded framing/parser emulation. `app.py` is only the explicit dispatcher. Cowrie is an independent runtime providing the SSH/Telnet VEG-200 low-interaction emulated shell.

## Data lifecycle

1. A bounded interaction reaches a Pi decoy.
2. The decoy writes structured JSONL (Cowrie writes its native JSON).
3. Filebeat annotates and durably queues the record.
4. Logstash parses, normalizes and indexes it or dead-letters it.
5. Session jobs use source IP and a configurable inactivity timeout (default five minutes).
6. Rules return reasons and evidence IDs; no opaque score is used.
7. Experiments reference matching immutable telemetry rather than altering it.

## Derived-data processor

FastAPI starts one lightweight asynchronous processor with its application lifespan. Every configured interval it reads the bounded event corpus, reconstructs sessions deterministically, and upserts sessions and detections under stable content-derived IDs. Repeating a cycle after a restart overwrites the same derived documents instead of duplicating them. The processor never updates event documents. Its last run, error, and write counts are exposed through `/system/status`.

## Telemetry integrity

An idempotent `elasticsearch-setup` Compose job installs explicit templates before
Logstash starts. Normalized schema-v1 records enter daily immutable raw event indices;
validation failures enter daily dead-letter indices. The processor reads but never
updates raw records and filters loopback/internal telemetry before creating schema-v1
sessions and detections. `/system/status` reports dead-letter volume (zero when no
index exists). Existing schema-less historical documents remain readable.


## Where to read the code

1. `sensor/docker-compose.yml` defines the fixed Pi topology and boundaries.
2. `sensor/honeypots/app.py`, then `common/server.py`, show dispatch, bounded reads, lifecycle, and logging.
3. Individual persona directories define protocol behavior; `cowrie/` owns SSH/Telnet identity.
4. `sensor/filebeat/filebeat.yml`, `elk/logstash/pipelines/`, and Elasticsearch templates show collection, normalization, validation, and storage.
5. Backend `processor.py`/`sessionizer.py`, then `detector.py`, show derived sessions and explainable detections.
6. Experiment routers and `evaluation/` show ground truth, cohorts, metrics, and reports.
7. `frontend/src/lib/api.ts` and pages show presentation over the sole API.
8. `attacks/runner/run.py` shows target validation usage and persona-aware bounded traffic.

See `PERSONAS.md` for file-level persona ownership and fidelity limits.
