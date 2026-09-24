# TRAPSIG Architecture Inventory

Status: first-pass inventory only. No application code was modified for this inventory.

## Evidence boundary

This inventory is based on source, configuration, documentation, and test references in the workspace. Runtime services and the physical lab were not started during this pass. A finding marked `candidate` requires verification during the migration phase.

## Current architecture

| Component | Location | Purpose | Runtime | Called by | Calls / data source | Status | Canonical? | Duplicate? | Deprecated? | Replacement | Action |
|---|---|---|---|---|---|---|---|---|---|---|
| Root dashboard UI | `src/app`, `src/components/ids` | TRAPSIG SOC/research console: overview, honeypots, events, sessions, detections, models, experiments | Next.js 16 / React 19 | Browser | `/api/ids/*` routes and `src/lib/ids-data` | Implemented and covered by root/inner regression tests | Candidate canonical UI | Yes, with inner Vite UI | No evidence | Keep during migration | Confirm consumer coverage, then retire duplicate UI |
| Root IDS API routes | `src/app/api/ids` | Browser-facing API facade for mode, telemetry, models, campaigns, Pi control, and demo data | Next.js server routes | Root UI and tests | `src/lib/ids-data`; FastAPI for live state/control; local files for demo/research metadata | Implemented; several routes are thin wrappers, while adapter also contains presentation/data behavior | Candidate facade only | Yes, with FastAPI endpoint domains | No | Thin proxy or remove after migration | Map every route to FastAPI contract |
| Root IDS data adapter | `src/lib/ids-data/index.ts` | Empty/demo/live mode handling, FastAPI forwarding, local demo/model/scenario reads, audit/status cache | Next.js server runtime | Root routes | FastAPI, CSV, JSON scenario/model files, global process state | Implemented and explicitly protects mode semantics | Not a backend source of truth | Yes, with FastAPI and inner Vite data access | No | Keep only facade/presentation concerns | Move domain ownership to FastAPI; preserve mode invariants |
| Prisma scaffold | `prisma/schema.prisma`, `src/lib/db.ts` | Generic SQLite `User`/`Post` starter schema and client | Next.js server runtime | No production/test imports found beyond its own definitions | SQLite via `DATABASE_URL` | Appears unused | No | No IDS duplicate, but unrelated scaffold | Candidate deprecated | None | Prove with final search, then remove dependency/schema |
| FastAPI API | `iot-honeypot-ids/dashboard/api/app/main.py` | Health, mode, events, sessions, detections/lineage, campaigns, features, models, experiments, anomaly, replay, honeypot control | Python/FastAPI | Root adapter; inner Vite directly; integration/unit tests; deployment compose | Elasticsearch, model registry, ML runtime modules, Pi SSH/control client, attacker scripts | Implemented and tested | Candidate canonical API | Yes, with root route facade and mini-service | No | Canonical service API | Define contract and make root routes explicit proxies |
| Inner Vite dashboard | `iot-honeypot-ids/dashboard/frontend/src/App.tsx` | Lightweight companion UI for API tables and replay | Vite / React 18 | Browser directly | FastAPI at `VITE_API_URL`, Kibana link | Implemented but feature-limited; no dashboard tests found | No, pending contrary evidence | Yes, with root UI | Not marked deprecated in source | Archive or migrate useful gaps | Do not run as second production dashboard |
| Runtime ML | `iot-honeypot-ids/dashboard/ml` and API imports | Feature extraction, rules, anomaly, hybrid detection | Python imported by FastAPI | FastAPI detection/training routes | Events/sessions, registry, configured model files | Implemented | Runtime canonical candidate | Shared with research imports per package README | No | Separate runtime inference from research training | Verify imports and feature registry ownership |
| Research ML | `iot-honeypot-ids/model-lab/model_lab` | Datasets, experiments, evaluation, replay, training artifacts | Python CLI/library | Research scripts and model-lab tests/docs | Elasticsearch replay, CSV datasets, experiment/model files | Implemented with historical artifacts | Research canonical candidate | Algorithms may overlap runtime | No | Keep separate from request-time API training | Document boundary; remove runtime training imports if present |
| Elasticsearch | `iot-honeypot-ids/dashboard/elasticsearch`, compose | Telemetry, sessions, detections, model/research backend indices/templates/ILM | Docker Elasticsearch 8.13.4 | Logstash, FastAPI, scripts | Persistent volumes and index templates | Configured; physical operation not validated | Yes | Possible stale template/config variants | Unknown | One validated config | Inventory templates and pipelines before cleanup |
| Logstash | `iot-honeypot-ids/dashboard/logstash` | Beats ingestion and normalization from Pi | Docker Logstash | Filebeat on Pi | TCP/Beats input, Elasticsearch output, dead-letter/error pipeline | Configured; physical operation not validated | Yes | Possible stale config | Unknown | One pipeline/schema | Validate all field names and version syntax |
| Kibana | `iot-honeypot-ids/dashboard/kibana` | Raw telemetry visualization and saved objects | Docker Kibana | Operators and inner Vite link | Elasticsearch | Configured; physical operation not validated | Yes | No second Kibana found | No | Keep as observability surface | Reconcile docs and saved objects |
| Pi honeypot fleet | `iot-honeypot-ids/pi/honeypots` | Cowrie, camera, IoT deception services | Docker on Raspberry Pi | Pi compose/scripts | Local logs, collector/Filebeat | Implemented/configured | Yes | No equivalent root runtime | No | Keep | Validate scripts and health checks on Pi later |
| Pi Filebeat/collector | `iot-honeypot-ids/pi/filebeat`, `pi/collector` | Durable telemetry forwarding and optional spool | Docker on Pi | Honeypot logs and Pi scripts | Logstash TCP/Beats, local queue/spool | Implemented/configured | Yes | No root equivalent | No | Keep | Preserve queue reliability during changes |
| Attacker tooling | `iot-honeypot-ids/attacker` | Lab-constrained reproducible scenarios | Python/shell on attacker host | Scripts, replay endpoint | Configured target/subnet and honeypot protocols | Implemented; `_deprecated` also exists | Yes for active tree | Possible scenario duplication | `_deprecated` requires consumer proof | Archive only after proof | Audit imports and target safety |
| Physical deployment scripts | `iot-honeypot-ids/pi/scripts`, `scripts/deployment` | Pi lifecycle and analysis-host orchestration | Shell | Operators/docs | Docker, SSH, compose, env config | Implemented with documented mismatch risk | Candidate per host | Possible duplicate status/start semantics | Unknown | One command set per host | Compare docs to executable files |
| Mini API | `mini-services/ids-api/main.py` | Small standalone FastAPI demo/service | Python/FastAPI | No consumers found in targeted search | In-memory/demo service per source/docs | Separate workspace artifact | No | Yes, API functionality overlaps | Candidate deprecated | None | Prove no consumer before removal/archive |
| Root examples | `examples/websocket` | Generic websocket sample | Next/Node sample | No TRAPSIG consumers | In-memory sample users/messages | Not IDS runtime | No | No IDS duplicate | No | Keep outside refactor scope or classify sample | Exclude from production architecture |

## Requested inventory areas

### A-D: applications, routes, and frontends

- The workspace root is a complete Next.js application with approximately 30 IDS route directories under `src/app/api/ids` and an IDS-focused page/component set.
- The inner repository is the research runtime and contains FastAPI, ELK configuration, Pi deployment, attacker tooling, model-lab, research, shared schemas, and tests.
- FastAPI currently exposes 37 decorated routes in `dashboard/api/app/main.py`, including `/health`, `/mode/*`, `/events`, `/sessions`, `/detections`, `/campaigns`, `/features`, `/models`, `/experiments`, `/anomaly`, `/replay`, and `/honeypots`.
- The inner Vite UI directly calls FastAPI and currently has pages for overview, sessions, detections, models, experiments, and replay. It does not expose the root UI's honeypot, live-events, campaign, or explicit mode/demo workflows.

### E-F: ML modules and scientific controls

- Runtime modules are in `dashboard/ml` and are imported by the FastAPI application.
- Research modules are in `model-lab/model_lab`; experiment JSON and model artifacts are present under `model-lab/experiments` and `model-lab/models`.
- Existing source/docs/tests explicitly mention leakage audits, feature provenance, label provenance, session materialization, mode gates, model activation status, bounded E2E polling, and lineage. These are preservation constraints, not cleanup targets.

### G-I: ELK

- Elasticsearch, Logstash, and Kibana are all under `iot-honeypot-ids/dashboard` and referenced by compose, deployment scripts, and architecture docs.
- The pinned Elasticsearch version is documented as 8.13.4. The first pass did not change or validate running containers.
- `dashboard/logstash/pipelines/beats.conf` is the apparent Pi-to-ELK ingestion path; `errors.conf` is a dead-letter/error path and must not be removed without pipeline validation.

### J-L: Pi, attacker, research

- Pi runtime owns honeypots, collector, Filebeat, configuration, Dockerfiles, and lifecycle scripts.
- Active attacker code is under `attacker`; `attacker/_deprecated` is a deletion candidate only after import/consumer proof.
- Research code and artifacts are under `research`, `model-lab`, and related shared schemas/docs. Physical validation is explicitly reported as not run in existing research documentation.

### M-O: tests and generated artifacts

- Inner tests are organized into `tests/unit`, `tests/integration`, and `tests/e2e`, with many pass-specific historical regression tests.
- Root tests include Next.js forwarding and mode-coherence checks. These tests are direct evidence that the root UI facade currently matters.
- Workspace artifacts include `.next`, `node_modules`, `tool-results`, `upload`, `download`, and `public/folder-tree.json`. They require classification; no generated artifact was deleted in this pass.
- Model experiment JSON, figures, reports, datasets, and physical-validation documents are research artifacts and must not be treated as disposable build output.

### P-Q: sample data and configuration

- Demo/sample paths include `model-lab/datasets`, `data/sample-telemetry`, `scripts/development/import-sample-data.sh`, and root adapter demo loading.
- The root adapter and FastAPI runtime both express `EMPTY`, `DEMO`, and `LIVE` semantics. The backend documents itself as authoritative; this must be retained during consolidation.
- Configuration exists at root/inner, dashboard, Pi, and attacker levels. Runtime values such as `FASTAPI_URL`, `VITE_API_URL`, `PI_IP`, and `CENTRAL_SERVER_IP` are configuration-driven in the inspected paths, though documentation and test fixtures contain localhost/private examples.

### R: security/configuration risks

- Secret-bearing names are present in configuration and tests (`API_SECRET_KEY`, SSH key paths, credentials files). Values were not copied into this report.
- FastAPI has an API-key dependency for mutating routes, IP allow-list middleware, restricted CORS origins, and explicit comments about test-only bypasses. These controls are high-risk preservation points.
- Attacker replay is exposed through the FastAPI API and must retain target-subnet validation and dry-run/safety behavior; do not broaden it during UI migration.
- A dedicated secret scan and hardcoded-network classification remain required before any deletion.

## Canonical candidates

| Concern | Candidate | Evidence | Confidence |
|---|---|---|---|
| Dashboard UI | Root Next.js app | More complete navigation and active root tests for API forwarding/mode coherence | Medium-high |
| API | Inner FastAPI | Owns ES, ML, Pi, sessions, detections, models, experiments, and explicit route contracts | High |
| Telemetry backend | Elasticsearch through Logstash | Pi Filebeat and dashboard pipeline/configuration | High |
| Runtime ML | `dashboard/ml` | Imported by FastAPI and described as runtime package | High |
| Research ML | `model-lab/model_lab` | Experiments, datasets, evaluation, model artifacts | High |
| Feature/provenance schemas | `shared/schemas` plus existing runtime feature code | Existing tests/docs enforce provenance/leakage semantics; exact single registry still needs consolidation | Medium |

## Proposed migration/deletion inventory (not executed)

| Candidate | Proposed action | Proof required first |
|---|---|---|
| `iot-honeypot-ids/dashboard/frontend` | Archive/remove as second production UI after any unique useful behavior is mapped | Consumer search, build/docs references, feature comparison |
| Root `src/app/api/ids/*` | Convert to explicit FastAPI proxies or remove after root UI migration | Route-by-route consumer and contract map |
| `prisma/schema.prisma`, `src/lib/db.ts`, Prisma dependency | Remove if final whole-workspace search confirms no consumer | Imports, scripts, tests, package/lock references |
| `mini-services/ids-api` | Archive/remove if no active consumer | Workspace references and deployment references |
| `attacker/_deprecated` | Archive/remove only if no active import | Imports, scripts, docs, tests |
| `.next`, `node_modules`, `tool-results`, `upload`, duplicate ZIPs | Classify as generated/local artifacts; do not delete useful research assets blindly | Git tracking, references, research-asset classification |

## Risks and open questions

1. The root adapter reads local research/demo files while FastAPI reads Elasticsearch and model registry files. A proxy migration could change empty/demo/live behavior if done without contract tests.
2. The inner Vite UI calls FastAPI directly and may be referenced by deployment docs even though source search shows lower feature coverage.
3. The FastAPI file contains broad exception handling in some endpoints; error-schema cleanup must preserve honest infrastructure failure states.
4. Model artifacts include legacy/demo and experiment outputs. They must be classified, not deleted by age or naming alone.
5. Physical telemetry flow, Pi resource use, and real detections remain unvalidated in this pass.
