# Final freeze report

## Repository and architecture

- Repository: `namelessweakl1ng/IOT-honeypot-IDS`.
- This report is included by the freeze commit; its immutable SHA is recorded in Git metadata and in the final response.
- Authoritative UI: root Next.js application (`src/`).
- Authoritative domain API: nested FastAPI application (`iot-honeypot-ids/dashboard/api`).
- Telemetry source of truth: Elasticsearch; ingestion: Pi Filebeat -> Logstash.
- Research/runtime tree: `iot-honeypot-ids/`.

## Data and benchmark protocol

IoT-23 (version 1.0.0) is selected as a complementary public network-flow benchmark because it contains labeled Zeek connection flows from 20 malicious and 3 benign scenarios. It is not Pi honeypot telemetry. Raw archives stay outside Git. The adapter preserves native labels, scenario and source provenance; explicit mappings and a conservative flow feature compatibility contract are documented. Evaluation holds out entire scenarios with zero overlap, preserves an untouched test set, and reports macro and per-class results alongside FPR/FNR and a confusion matrix.

TRAPSIG Pi campaigns form a separate controlled deployment benchmark. Campaign ground truth is independent of rule/classifier/anomaly predictions. The physical lab is NOT RUN in this environment.

## Detection, models, software, and security

Runtime detection design includes rule, supervised, anomaly, and hybrid components. IoT-23 supports only separately justified flow classifier/anomaly experiments; Pi-specific event rules are not applied to it by implication. Synthetic training labels are rejected by the research experiment runner. Model activation remains registry-gated. The demo uses unique local secrets and explicit DEMO/LIVE mode boundaries.

## Verification and known limits

- Python unit suite: 874 passed, 2 warnings.
- Root frontend lint and production build: PASS.
- Compose validation and edited shell syntax: PASS.
- IoT-23 content download/preparation and benchmark artifacts: NOT RUN; adapter tests use deterministic fixtures.
- Pi, Filebeat, ELK, runtime detection, lineage over physical telemetry: NOT RUN.
- CPU, RAM, temperature, load, disk, network/container resources and T0-T9 latency: NOT RUN.
- Supported claims and wording: [CLAIMS_AUDIT.md](CLAIMS_AUDIT.md).
- Known limits: network-flow and honeypot-session domains differ; scenario correlations and class imbalance; dataset labels are analyst-derived; anomaly detection does not prove zero-day exploitation; public results do not establish production performance; controlled attacks do not represent the whole Internet.

See [FINAL_VERIFICATION_REPORT.md](FINAL_VERIFICATION_REPORT.md) for command-by-command outcomes.