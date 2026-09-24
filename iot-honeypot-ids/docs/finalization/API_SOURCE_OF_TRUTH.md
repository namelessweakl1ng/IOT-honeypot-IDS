# API Source of Truth

FastAPI is the sole domain API. The root Next.js routes are a server-side browser facade during the transition and must not own independent telemetry, session, detection, campaign, model, experiment, ML, or Pi business logic.

| Old route/system | Canonical route | Consumer | Migration | Status |
|---|---|---|---|---|
| `src/app/api/ids/health` and system status | `GET /health` | Root overview/system UI | Forward backend status and preserve failure state | Proxy/transitional |
| `src/app/api/ids/mode`, demo, live | `GET /mode`, `POST /mode/live`, `/mode/demo`, `/mode/reset` | Root mode controls and tests | Backend owns state; facade forwards authenticated transitions | Proxy/transitional |
| `src/app/api/ids/events` and live views | `GET /events` | Root live events | FastAPI queries Elasticsearch | FastAPI canonical |
| `src/app/api/ids/sessions`, `[id]` | `GET /sessions`, `GET /sessions/{session_id}` | Root sessions; tests | FastAPI/session materializer owns documents and lineage | FastAPI canonical |
| `src/app/api/ids/detections`, `[id]` | `GET /detections`, `GET /detections/{detection_id}`, lineage route | Root detections; tests | FastAPI returns stored detection and lineage | FastAPI canonical |
| `src/app/api/ids/campaigns`, `[id]` | `GET /campaigns`, `GET /campaigns/{campaign_id}`, `POST /campaigns/correlate` | Root campaign views/tests | FastAPI campaign correlator owns relationships | FastAPI canonical |
| `src/app/api/ids/features` | `GET /features/schema`, `GET /features/{session_id}` | Root model/session views | FastAPI runtime feature extractor owns schema | FastAPI canonical |
| `src/app/api/ids/models` | `GET /models`, `/models/active`, `/models/{model_id}`, `POST /models/{model_id}/status` | Root models; tests | FastAPI registry owns validity and activation | FastAPI canonical |
| `src/app/api/ids/experiments` | `GET /experiments`, metrics/training endpoints | Root experiments; tests | FastAPI exposes artifacts; model-lab owns research execution | FastAPI canonical |
| `src/app/api/ids/anomaly` and detection actions | `/detect/rule/{session_id}`, `/detect/anomaly/{session_id}`, `/detect/hybrid/{session_id}`, `/anomaly/*` | Root ML controls/tests | FastAPI runtime detector owns fusion and persistence | FastAPI canonical |
| `src/app/api/ids/honeypots`, Pi routes | `GET /honeypots`, `POST /honeypots/{id}/start|stop|restart` | Root honeypot controls; tests | FastAPI Pi client owns SSH safety and status | FastAPI canonical |
| `src/app/api/ids/scenarios`, replay | `POST /replay` plus attacker scenario metadata | Root replay controls | FastAPI is control boundary; attacker runner validates target | FastAPI canonical |

## Response rules

- Successful list endpoints use explicit envelopes such as `events`, `sessions`, `detections`, `models`, or `experiments` plus pagination metadata where applicable.
- Infrastructure failures are not converted to `200` with empty data.
- Mutations require the configured API key; the root server forwards it and never exposes it to the browser.
- Detection responses preserve detector, detector version, prediction, confidence/anomaly score, decision source/reason, timestamps, and available campaign/session/event lineage.
- Ground-truth label and source remain separate from rule, classifier, anomaly, and final predictions.
