# Final Architecture Decision

Status: implementation-freeze baseline. This decision is based on source, tests, configuration, and documentation inspection. Physical deployment was not executed.

## Decision

The repository keeps the root Next.js application as the single authoritative dashboard UI and keeps the nested `iot-honeypot-ids` tree as the authoritative research/runtime project. FastAPI is the single domain API. Elasticsearch is the telemetry source of truth. Logstash is the Pi ingestion boundary. Runtime inference remains in `dashboard/ml` and the FastAPI service; training and evaluation remain in `model-lab`.

The root application is not an unrelated starter: its IDS pages cover overview, honeypots, live events, sessions, detections, models, experiments, mode transitions, demo controls, and Pi controls. Root tests cover server-side API-key forwarding and backend-owned mode coherence. The nested Vite UI is a smaller companion implementation and is not retained as a second production dashboard.

## Component inventory

| Component | Current location | Consumers | Purpose | Canonical? | Duplicate? | Deprecated? | Action |
|---|---|---|---|---|---|---|---|
| Dashboard UI | `src/app`, `src/components/ids` | Browser, root tests | Authoritative SOC/research console | Yes | No after Vite retirement | No | Retain |
| Browser API facade | `src/app/api/ids`, `src/lib/ids-data` | Root UI, root tests | Server-side forwarding and explicit demo presentation boundary | Transitional | Overlaps FastAPI domains | No | Keep only thin proxies/presentation behavior |
| Domain API | `iot-honeypot-ids/dashboard/api/app` | Root facade, direct tests, deployment | Health, telemetry, sessions, campaigns, detections, models, ML, Pi control | Yes | Previously overlapped root routes | No | Retain as source of truth |
| Vite dashboard | `iot-honeypot-ids/dashboard/frontend` | Optional compose dev profile | Smaller direct-to-FastAPI UI | No | Yes | Yes | Remove from active runtime after reference audit |
| Elasticsearch | `iot-honeypot-ids/dashboard/elasticsearch` | Logstash, FastAPI, Kibana | Telemetry, sessions, detections, indices | Yes | No | No | Retain and validate config |
| Logstash | `iot-honeypot-ids/dashboard/logstash` | Pi Filebeat | Ingestion, normalization, dead-letter routing | Yes | No | No | Retain |
| Kibana | `iot-honeypot-ids/dashboard/kibana` | Operators | Search/visualization | Yes | No | No | Retain |
| Runtime ML | `iot-honeypot-ids/dashboard/ml`, API modules | FastAPI | Feature extraction, rule/anomaly/hybrid inference | Yes | Research algorithms are related but separate | No | Retain runtime boundary |
| Research ML | `iot-honeypot-ids/model-lab/model_lab` | Model-lab scripts/tests | Dataset, split, training, evaluation, artifacts | Yes for research | No runtime UI duplicate | No | Retain; no request-time training dependency |
| Pi runtime | `iot-honeypot-ids/pi` | Operators, Filebeat | Honeypots, collector, forwarding, lifecycle | Yes | No | No | Retain |
| Attacker runtime | `iot-honeypot-ids/attacker` | Operators, replay | Lab-constrained scenarios and campaign metadata | Yes | `_deprecated` is historical | Partial | Retain active tree; classify archive |
| Mini API | `mini-services/ids-api` | No active consumer found | Synthetic standalone API | No | Yes | Yes | Archive/remove after final reference check |
| Prisma scaffold | `prisma/schema.prisma`, `src/lib/db.ts` | No application consumer found | Generic User/Post starter database | No | No IDS value | Yes | Remove with unused dependency if final search remains clean |
| Generated workspace material | `tool-results`, `upload`, local caches | No runtime consumer | Tool dumps/pasted prompts/build output | No | No | Yes | Remove from tracked project or keep outside source policy |

## Physical topology

```text
Computer 1: Raspberry Pi
  honeypots -> Filebeat/collector -- TCP/Beats -->
Computer 2: Fedora analysis host
  Logstash -> Elasticsearch/Kibana -> FastAPI -> Next.js dashboard
Computer 3: controlled attacker
  attacker scenarios -> Pi honeypots
```

Runtime addresses are configuration values. The intended lab values are not embedded in application logic. Physical validation remains NOT RUN.

## Freeze invariants

- `EMPTY`, `DEMO`, and `LIVE` are explicit backend-owned modes.
- Synthetic data is never silently presented as live telemetry.
- Rule output is detector output, not ground truth.
- `NO_RULE` is not `BENIGN`; unlabeled data remains unknown.
- Leaky features remain excluded from leakage-safe research feature version `v2`.
- Experiment metadata records dataset, feature version, seed, split strategy, and commit where available.
- Model activation requires explicit registry status; invalid historical artifacts remain invalid.
- Detection lineage remains campaign -> event -> session -> features -> detector -> detection.
- Physical telemetry, latency, resource use, and external-dataset results are not claimed without measurements.
