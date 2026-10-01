# Research traceability

This document connects research questions to inspectable implementation and evidence. It defines what can be measured; it does not report uncollected results.

| Research objective | Implemented mechanism | Representative scenarios / experiment | Metric or evidence | Generated artifact | Limitation |
| --- | --- | --- | --- | --- | --- |
| Multi-protocol IoT deception | Five fixed honeypots expose six logical SSH, Telnet, HTTP, TCP, and MQTT services | `multi-honeypot-attack` | services reached and normalized protocol events | `trapsig-events-*`, reconstructed session | Bounded fictional emulation is not a physical device or full protocol stack |
| Attack-behavior collection | Cowrie plus custom JSONL telemetry normalized by Logstash | credential, web, IoT, MQTT, and Cowrie interaction scenarios | authentication attempts, paths, MQTT operations, IoT operations, Cowrie commands | immutable event documents and dead-letter records | Only defined lab interactions and retained fields are observed |
| Deterministic attack detection | Explainable versioned rules over canonical events/sessions | scenario matrix below | rule IDs, reasons, evidence event IDs, session IDs | `trapsig-detections` | Rules are fixed heuristics, not claims about unknown attacks |
| Multi-service correlation | Source-IP sessionization and `services_touched` | `cross-service-recon`, `multi-stage`, `multi-honeypot-attack` | service count, `MULTI_SERVICE_ACTIVITY`, `MULTI_STAGE_ATTACK` | `trapsig-sessions`, detections | NAT/shared addresses can combine actors; configured timeout bounds a session |
| Detection effectiveness | Ground truth and attack/control matrix evaluation | repeated attacks and controls | TP, TN, FP, FN, precision, recall, F1, specificity, false-positive rate, accuracy | experiment records and evaluation report | Valid only for the tested cohort, repetitions, and scenarios |
| Timing | Occurrence, ingestion, processing, evidence, detection, and settle timestamps | completed experiment batches | evidence, detection, processing, ingestion latency and settle duration | experiment records and report tables | Requires synchronized clocks and complete ingestion |
| Resource overhead | `evaluation.resources` samples Docker/container hosts | Fedora/laptop and Raspberry Pi measurement runs | CPU and RAM observations | resource CSV files | **NOT MEASURED** until physical testing is performed |
| Recovery / reliability | Idempotent backend writes and Filebeat disk buffering | backend restart, Logstash interruption, Filebeat buffered-delivery experiments | duplicate/missing IDs and delivery/recovery observations | events, derived indices, experiment notes | Must be performed on the physical topology; recovery completeness is not assumed |
| Reproducibility | Immutable manifest identity and configuration cohort | every catalog-backed experiment | scenario SHA-256, ruleset/schema version, software revision, configuration cohort, batch ID, ground-truth run ID | scenario manifest, run JSON, experiment document, report | Reproduction still depends on recorded hardware, configuration, clocks, and retained data |

## Scenario-to-detection contract

| Scenario | Primary `expected_detection` |
| --- | --- |
| `ssh-bruteforce` | `BRUTE_FORCE` |
| `ssh-interaction` | `COMMAND_INTERACTION` |
| `camera-recon` | `WEB_ENUMERATION` |
| `camera-default-creds` | `DEFAULT_CREDENTIALS` |
| `router-recon` | `WEB_ENUMERATION` |
| `router-default-creds` | `DEFAULT_CREDENTIALS` |
| `iot-probe` | `RECONNAISSANCE` |
| `iot-default-creds` | `DEFAULT_CREDENTIALS` |
| `mqtt-recon` | `MQTT_PROBING` |
| `cross-service-recon` | `MULTI_SERVICE_ACTIVITY` |
| `multi-stage` | `MULTI_STAGE_ATTACK` |
| `multi-honeypot-attack` | `MULTI_STAGE_ATTACK` |

Controls are `camera-control`, `router-control`, `iot-control`, `mqtt-control`, and `ssh-control`; their primary expectation is `null`. `http-enumeration`, `mqtt-auth-probe`, and `telnet-auth-attempts` remain focused compatibility scenarios. A scenario may legitimately trigger secondary rules, which remain visible; `expected_detection` is only its primary evaluation expectation.

## Evidence discipline

Do not infer performance from CI or synthetic fixtures. Fedora CPU/RAM, Raspberry Pi CPU/RAM, accuracy, latency, throughput, and recovery results remain **NOT MEASURED** until the prescribed physical repetitions are collected. Report the cohort, software revision, hardware, time synchronization evidence, repetitions, exclusions, and inconclusive runs beside any future result. TRAPSIG does not currently claim superiority, a particular accuracy, or lightweight operation.
