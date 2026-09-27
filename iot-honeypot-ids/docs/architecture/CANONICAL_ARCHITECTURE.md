# Canonical architecture

The repository has one production operator interface and one IDS domain API.

```text
Pi honeypots -> collector / Filebeat -> analysis-host Logstash -> Elasticsearch
                                                        |            |
                                                        +-> FastAPI <-+
                                                              ^
                                              root Next.js UI --+
```

| Responsibility | Canonical location | Consumers | Source/state |
|---|---|---|---|
| Production dashboard | repository root `src/` | operator browser | Next.js app; forwards IDS requests through server routes |
| IDS API | `iot-honeypot-ids/dashboard/api/app/` | root Next.js server and operators | FastAPI; authoritative IDS-domain API |
| Physical telemetry and honeypots | `iot-honeypot-ids/pi/` | Filebeat and Logstash | Pi containers; controlled lab only |
| Runtime rules, features, sessions, fusion | `iot-honeypot-ids/dashboard/api/app/` | API and session scheduler | Python runtime implementation |
| Offline model development | `iot-honeypot-ids/model-lab/` | research commands and model registry | dataset-aware research code; does not replace runtime feature extraction |
| Research protocol and evidence | `iot-honeypot-ids/research/`, `iot-honeypot-ids/docs/research/` | researchers | manifests/protocols are tracked; run outputs and raw datasets are ignored |
| Attacker scenarios | `iot-honeypot-ids/attacker/` | isolated lab operator | bounded, allow-listed traffic generation |

The nested `dashboard/` is the runtime/API deployment directory. Any legacy UI source under it is not the production dashboard. `dashboard/ml/` is a legacy/offline compatibility area; runtime decisions are made by `dashboard/api/app/`. `model-lab/` owns offline training/evaluation and has its own domain-specific IoT-23 flow adapter. The root `src/app/api/ids/` routes are a same-origin transport layer, not a second IDS API or independent data store.

Synthetic sample telemetry exists only under `iot-honeypot-ids/examples/demo/` and is a developer/demo fixture. `PUBLIC_DATASET`, `CONTROLLED_LAB`, `LIVE_TELEMETRY`, and `SYNTHETIC` are distinct evidence categories. A backend failure is not an empty detection result.

## Principal risks and boundaries

- UI proxy routes and FastAPI routes can drift; FastAPI remains the IDS authority and route contract tests should cover proxy forwarding.
- Runtime and research feature vectors intentionally differ because honeypot sessions and network flows are different observation units.
- Legacy experiment/model artifacts remain tracked as historical development examples; they are not physical or public-dataset evidence and must not be activated without current provenance/registry checks.
- No physical validation or real IoT-23 experiment is implied by the presence of code, schemas, or fixtures.
