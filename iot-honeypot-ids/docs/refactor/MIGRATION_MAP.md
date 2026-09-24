# TRAPSIG Migration Map

Status: inventory-stage map. Entries are proposed migrations; no migration or deletion was executed.

| Old path/system | Proposed new authority | Consumers found | Status | Proof before change |
|---|---|---|---|---|
| Root `src/app/api/ids` domain routes | `dashboard/api/app/main.py` via thin Next proxy or direct configured API | Root IDS components; root tests; some inner tests reference the facade | PROPOSED | Route-by-route contract tests |
| `src/lib/ids-data` live integrations | FastAPI services (`es_client`, runtime mode, registry, Pi client) | Root route handlers | PROPOSED | Preserve mode/error/lineage tests |
| Root local demo/model/scenario reads | Explicit DEMO fixture boundary; FastAPI remains mode authority | Root demo/model/scenario pages | PROPOSED | Synthetic markers and no LIVE fallback tests |
| `iot-honeypot-ids/dashboard/frontend` | Root Next UI | Inner dashboard docs/build and possible operators | PROPOSED | Feature comparison, docs/reference search, build decision |
| `prisma/schema.prisma` `User`/`Post` | Remove starter scaffold if unused | No application consumers found in first pass | PROPOSED | Full import/package/generated-client search |
| `src/lib/db.ts` | Remove with Prisma scaffold if unused | No consumers found in first pass | PROPOSED | Full import search |
| `mini-services/ids-api` | FastAPI canonical API or archive as standalone example | No TRAPSIG consumer found in first pass | PROPOSED | Deployment/docs/reference search |
| `dashboard/ml` runtime inference | Remains FastAPI runtime boundary | `main.py` imports runtime modules | RETAIN | Verify feature registry and training imports |
| `model-lab/model_lab` training/evaluation | Remains research-only boundary | Research scripts, experiment docs/tests | RETAIN | Verify no request-time training dependency |
| `model-lab/models/*` | Classify into active/validated/experimental/retired/invalid metadata categories | Registry, experiments, docs, tests | PROPOSED | Read metadata and activation gate before moves |
| `attacker/_deprecated` | Archive or remove only after proof | Search required; no active import established | PROPOSED | Import and script reference audit |
| `data/sample-telemetry` and import script | Explicit DEMO/REPLAY fixtures | Demo/development tooling | RETAIN WITH LABELS | Confirm synthetic markers cannot enter LIVE |
| `tool-results`, `upload`, `download`, `.next`, local dependency/build output | Generated/local artifact policy | Workspace tooling | CLASSIFY | Git tracking and useful research asset audit |

## Preservation constraints

- Do not remove or weaken ExperimentRunner, temporal/session/campaign split controls, leakage rejection, label provenance, activation gates, lineage, bounded E2E polling, Filebeat queueing, or target validation.
- Do not classify physical tests as software tests. The physical lab remains NOT RUN in this inventory.
- Every deletion requires path, reason, consumers, tests, replacement, and safe-to-remove evidence.
