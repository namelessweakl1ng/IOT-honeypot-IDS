# API Consolidation Inventory

Status: first-pass comparison. No route implementation was changed.

## Authority decision

FastAPI in `dashboard/api/app/main.py` is the canonical domain API candidate. Root Next.js `/api/ids/*` routes are currently the browser facade and must become explicit, thin proxies or be removed after consumers migrate. The facade must not retain independent detections, sessions, campaigns, models, experiments, or telemetry business logic.

## Domain comparison

| Domain | Root Next route(s) | FastAPI route(s) | Current consumers | Data source | Duplicate behavior | Canonical implementation | Action |
|---|---|---|---|---|---|---|---|
| Health/status | `/health`, `/system-status` | `GET /health`, `GET /` | Root UI and tests | FastAPI/ES/model directory | Root formats/presents backend status | FastAPI health | Define stable response and proxy |
| Runtime mode | `/mode`, `/live/enter`, `/demo/load`, `/demo/clear` | `GET /mode`, `POST /mode/live`, `/mode/demo`, `/mode/reset` | Root UI, root mode tests | FastAPI runtime mode; local adapter cache | Both coordinate transitions; backend is documented authoritative | FastAPI mode state | Preserve transactional facade behavior, remove local authority |
| Events | `/events`, `/live/*` related UI calls | `GET /events` | Root live-events UI; Vite indirectly via API | Elasticsearch | Root adapter transforms/proxies | FastAPI ES query | Proxy with shared pagination/error schema |
| Sessions | `/sessions`, `/sessions/[id]` | `GET /sessions`, `GET /sessions/{id}`, materialization routes | Root sessions UI, Vite, tests | Elasticsearch/session materializer | Root response shaping vs FastAPI search | FastAPI/session materializer | Normalize envelope and lineage |
| Detections | `/detections`, `/detections/[id]` | `GET /detections`, `GET /detections/{id}`, lineage | Root detections UI, Vite, tests | Elasticsearch | Root adapter may provide demo/local shaping; FastAPI fetches lineage | FastAPI detection and lineage | Ensure dashboard never manufactures lineage |
| Campaigns | `/campaigns`, `/campaigns/[id]` | `GET /campaigns`, `GET /campaigns/{id}`, `POST /campaigns/correlate` | Root UI/API references and tests | Elasticsearch/correlation logic | Root route facade vs FastAPI correlator | FastAPI campaign correlator | Contract-map fields and provenance |
| Features | `/features`, `/features/[sessionId]` | `GET /features/schema`, `GET /features/{session_id}` | Root feature views/tests | FastAPI feature extractor/ES | Root may read local feature definitions | FastAPI feature schema/extraction | Establish one feature registry |
| Models | `/models`, `/models/[id]`, `/models/active` | `GET /models`, `/models/{model_id}`, `/models/active`, `POST /models/{model_id}/status` | Root models UI, Vite, tests | FastAPI model registry/files | Root local model metadata vs FastAPI registry | FastAPI registry and activation gate | Remove local authority after migration |
| Experiments | `/experiments` | `GET /experiments`, metrics/training routes | Root experiments UI, Vite, tests | Experiment artifacts/model-lab | Root local file listing vs FastAPI endpoint | FastAPI read contract; model-lab owns training | Keep training outside request-time UI |
| Detection engines | `/anomaly/*` and detection actions | `POST /detect/rule/{session_id}`, `/detect/anomaly/{session_id}`, `/detect/hybrid/{session_id}`, `/anomaly/train`, `GET /anomaly/status` | Root controls/tests | FastAPI runtime ML + ES | Potentially duplicated route orchestration | FastAPI runtime ML | Preserve rule/ground-truth distinction |
| Honeypots/Pi | `/honeypots`, `/pi/*`, `/pi/honeypots/*` | `GET /honeypots`, `POST /honeypots/{id}/start|stop|restart` | Root honeypot UI, tests | FastAPI Pi client/SSH | Root forwards control requests; no second Pi implementation found | FastAPI control plane | Keep auth, host-key, and status semantics |
| Demo/sample telemetry | `/sample-telemetry`, demo load/clear | No equivalent data authority; mode endpoints only | Root demo UI/tests | Root local synthetic CSV/JSON | Root can read synthetic data locally | Explicit demo fixture path | Keep synthetic and live stores distinct |
| Replay/scenarios | `/scenarios` | `POST /replay` | Root scenario/replay UI; Vite replay | Attacker scripts, target validation | Root route may enumerate files; FastAPI executes guarded replay | FastAPI control boundary + attacker runner | Audit subprocess and target safety |

## Required contract rules

- FastAPI owns domain state and integrations.
- Root routes must forward status codes, structured errors, pagination, timestamps, IDs, and backend lineage without inventing values.
- `RULE_PREDICTION` remains distinct from `GROUND_TRUTH`; `NO_RULE` is not `BENIGN`.
- `EMPTY`, `DEMO`, and `LIVE` are backend-owned runtime modes. `UNKNOWN` may only represent unreachable/uncertain presentation state.
- LIVE failures must remain visible as failures; the facade must not silently load synthetic data.
- Mutating requests retain API-key forwarding server-side. The browser must not receive the secret.

## Migration order

1. Freeze and test current root facade behavior.
2. Publish a typed/structured FastAPI contract for each domain above.
3. Convert one domain at a time to explicit proxy behavior.
4. Run focused root and inner tests after each domain.
5. Remove or archive only routes with no remaining consumer and a documented replacement.
