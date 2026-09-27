# Final implementation audit

Inventory covers the tracked root application and the nested IDS platform. This is an implementation inventory, not evidence that physical devices or public dataset contents were executed.

| Component | Purpose | Canonical location | Consumer | Data source | State | Risk | Action |
|---|---|---|---|---|---|---|---|
| Operator UI | Overview, events, sessions, detections, models, system | root `src/` | Browser | server-side same-origin IDS routes | Canonical | UI/API contract drift | Keep root UI authoritative; verify LIVE distinguishes empty/unavailable |
| IDS transport routes | Same-origin requests and secret forwarding | root `src/app/api/ids/` | Root UI | FastAPI, explicit DEMO fixtures | Proxy layer | Accidental second business API | Keep thin; IDS decisions belong to FastAPI |
| IDS API | Health, modes, event/session/model/detection/campaign endpoints | `iot-honeypot-ids/dashboard/api/app/` | Root proxy, operator scripts | Elasticsearch, runtime code | Canonical API | Service outage can resemble empty data if callers mishandle errors | Preserve explicit health/errors and auth for mutations |
| Runtime detection | Rules, optional classifier/anomaly, hybrid fusion, lineage | `dashboard/api/app/{rule_detector,hybrid_detector,anomaly_detector,feature_extractor}.py` | Session scheduler/API | Reconstructed honeypot sessions | Implemented; physical results NOT RUN | Detector output may be mistaken for ground truth | Keep provenance and reason separate |
| Session/campaign reconstruction | Link events to sessions and group sessions by source/time | `dashboard/api/app/{session_materializer,campaign_correlator}.py` | API and detectors | Indexed event/session records | Implemented; physical lineage NOT RUN | Campaign IDs can be inferred and differ from attacker run IDs | Verify links using returned IDs; never assume IDs match |
| Elasticsearch/Logstash | Durable indexing and normalization | `dashboard/docker-compose.yml`, `dashboard/{elasticsearch,logstash}/` | API, Kibana, Pi Filebeat | Pi telemetry | Configured; not running here | Image/runtime compatibility and credentials | Use configured versions and real service health checks |
| Pi honeypots and collector | Capture controlled interaction and emit telemetry | `pi/` | Filebeat | Isolated lab requests | Implemented; Pi NOT RUN | Container resource limits and log path drift | Preflight and record physical results |
| Filebeat | Forward Pi logs | `pi/filebeat/`, `pi/docker-compose.yml` | Logstash | Honeypot/collector logs | Configured; transport NOT RUN | Queue/restart/delivery behavior unmeasured | Exercise restart and interruption protocol |
| Attacker tools | Run scoped controlled scenarios | `attacker/` | Pi lab | Explicit configured target/subnet | Active scripts plus `_deprecated/` historical copy | Deprecated scripts/credential lists may confuse operators | Use only top-level active runner; deprecated copy is not canonical |
| Offline model code | Prepare datasets, split, train, evaluate | `model-lab/model_lab/` | Researcher | Public dataset or explicitly labeled development data | Implemented; IoT-23 not run | Historical artifacts could be misread as research results | Require provenance, split, seed, commit, and validity in each experiment |
| IoT-23 adapter | Read native Zeek labels/flows and normalize provenance | `model-lab/model_lab/datasets/import_iot23.py` and `iot23_features.py` | Validator and experiment runner | Local external IoT-23 archive | Adapter implemented; real data NOT RUN | Scenario/label leakage and partial downloads | Validate all scenarios, audit mapped labels/features, hold out scenarios |
| IoT-23 mapping/schema | Track explicit labels and canonical output contract | `research/datasets/iot23/{mappings.yaml,schema.json}` | Importer, docs | Native IoT-23 fields | Tracked | A mapping can overstate behavioral certainty | Preserve native label and mark analyst-derived dataset provenance |
| Research artifacts | Record protocol, measurements, hypotheses and manifests | `research/`, `docs/research/` | Researcher/evaluator | Generated only by real runs | Protocol/templates tracked; measurements absent | Templates can be mistaken for results | Generated outputs are ignored and marked NOT RUN until populated |
| Demo fixtures | Permit explicit UI development/demo | `examples/demo/sample-telemetry/` | DEMO path only | Synthetic fixtures | Labeled fixture | Confusion with physical evidence | Keep out of LIVE and research workflows |
| Root package/build | Build the Next.js operator UI | root `package.json`, `bun.lock`, `next.config.ts` | Developer/deployment pipeline | Checked-in Bun lock | Canonical UI toolchain | Windows-specific script assumptions | Cross-platform standalone copy helper; verify with stated runtime |
| Nested deployment docs/scripts | Start/stop/inspect services | `scripts/`, `pi/scripts/`, `dashboard/` | Lab operator | Local env files and Docker | Present | Duplicated or stale instructions | Use `DEMO.md` as the one primary college path; other docs are component references |
| Tests | Check UI proxy, API/runtime, leakage, safety and schema contracts | root `tests/`, nested `tests/` | Developers | Fixtures and optionally services | Software tests executed in recorded report | Fixture pass does not equal real-data/physical pass | Keep results categorized and integration skips visible |
| Generated images/legacy artifacts | Historical UI captures and model-lab records | root `scripts/*.png`, `model-lab/experiments/`, `model-lab/models/` | Audit/history only | Prior development runs | Tracked historical artifacts | Could be mistaken for current benchmark evidence | Retain only as UI/history fixtures; not cite as experimental evidence |

## Duplicate logic and stale-path findings

- Root Next.js API route handlers and nested FastAPI endpoints both contain request-level logic. They have distinct roles: same-origin transport/auth forwarding versus IDS business operations. FastAPI is canonical for IDS domain decisions.
- `dashboard/ml/` and `model-lab/` are separate older runtime/offline areas. Do not treat their feature schemas or models as interchangeable. Current online extraction is `dashboard/api/app/feature_extractor.py`; IoT-23 offline features are `model-lab/model_lab/datasets/iot23_features.py`.
- The attacker tree contains `_deprecated/` and active scripts. Only `attacker/run-scenario.sh` is referenced by the primary procedure.
- Experiment/model JSON and metadata under model-lab are historical fixtures, not runs from the final freeze. The public dataset output directory and physical measurements are not populated with guessed results.
- Root images named `scripts/*.png` are tracked screenshots from prior UI review. They are not telemetry, model evidence, or current live-state screenshots.

## Status

The root UI, FastAPI API, runtime, research root, and primary demo path are now explicitly identified. IoT-23 content validation, physical lab verification, full service E2E, latency, and resource measurements remain pending real execution.
