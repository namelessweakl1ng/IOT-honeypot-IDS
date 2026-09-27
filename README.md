# TRAPSIG

TRAPSIG is an IoT honeypot and hybrid intrusion-detection research platform.
The repository has one authoritative dashboard: the root Next.js application in `src/`. The research/runtime project lives in `iot-honeypot-ids/` and owns the Raspberry Pi deployment, attacker scenarios, ELK configuration, FastAPI domain API, runtime ML, model-lab, research artifacts, shared schemas, and tests.

## Runtime authority

```text
Computer 1: Raspberry Pi honeypots -> Filebeat/collector
Computer 2: Fedora Logstash -> Elasticsearch/Kibana -> FastAPI
Computer 3: controlled attacker scenarios
Browser: root Next.js dashboard -> FastAPI
```

FastAPI is the domain API and Elasticsearch is the telemetry source of truth. The root `/api/ids/*` handlers are a server-side browser facade and must not become a second business-logic implementation.

## Modes and research integrity

`EMPTY`, `DEMO`, and `LIVE` are explicit backend-owned modes. Synthetic data is labeled and never silently used as live telemetry. Rule predictions remain separate from ground truth; `NO_RULE` is not benign; unlabeled data remains unknown. Leakage-safe feature version `v2` excludes the audited label-derived features.

## Start locally

```bash
bun install
bun run dev
```

The single operator demonstration path is [DEMO.md](DEMO.md). The FastAPI and ELK deployment instructions are in [iot-honeypot-ids/README.md](iot-honeypot-ids/README.md). The final architecture and research baseline are documented in:

- [Final architecture decision](iot-honeypot-ids/docs/finalization/FINAL_ARCHITECTURE_DECISION.md)
- [API source of truth](iot-honeypot-ids/docs/finalization/API_SOURCE_OF_TRUTH.md)
- [Research baseline](iot-honeypot-ids/docs/research/RESEARCH_BASELINE.md)
- [Claims audit](iot-honeypot-ids/docs/research/CLAIMS_AUDIT.md)
- [Verification report](iot-honeypot-ids/docs/research/FINAL_VERIFICATION_REPORT.md)
- [IoT-23 dataset card](iot-honeypot-ids/docs/research/datasets/IOT23_DATASET_CARD.md)
- [Final research freeze report](iot-honeypot-ids/docs/research/FINAL_FREEZE_REPORT.md)

Physical-lab validation is not implied by local builds or unit tests. The current baseline must explicitly report physical status and measured results.
