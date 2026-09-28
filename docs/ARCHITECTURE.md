# Architecture

There are two hosts. The Pi runs five containers representing six logical services (Cowrie supplies SSH and Telnet) plus Filebeat. Filebeat's disk queue is the sole edge buffer and sends JSON/JSONL over Beats to laptop Logstash. Per-family filters normalize records into the canonical schema; malformed records go to `trapsig-dead-letter-*`, never silently disappear.

Elasticsearch owns `trapsig-events-*`, `trapsig-sessions-*`, `trapsig-detections-*`, and `trapsig-experiments-*`. FastAPI is the only domain backend. Its focused routers query Elasticsearch, while services deterministically reconstruct source-IP sessions, apply explainable rules, correlate experiments, and invoke a fixed Pi management script through SSH. Next.js contains only presentation and a typed HTTP client. Kibana directly explores Elasticsearch for detailed research analysis.

The deployment deliberately has only the components in this document; no parallel messaging, storage, API, collector, runtime-mode, or model lifecycle exists.

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
