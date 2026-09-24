# Canonical Event Schema

The event schema is ECS-shaped and is validated by `shared/schemas/event_schema.py` and the Elasticsearch templates. Logstash normalizes Pi output before indexing. Missing required fields route to the dead-letter/error path rather than being treated as benign telemetry.

| Field | Type | Meaning | Producer | Consumer | Required | Sensitive |
|---|---|---|---|---|---|---|
| `@timestamp` | ISO-8601 UTC | Event occurrence time | Pi honeypot | Logstash, Elasticsearch, sessions | Yes | No |
| `event_id` | string | Stable event identifier | Pi/collector | Logstash, Elasticsearch, lineage | Yes | No |
| `session_id` | string | Interaction session identifier | Pi/correlation | Elasticsearch, materializer, detections | Yes | No |
| `campaign_id` | string | Controlled campaign correlation identifier | Attacker/campaign correlator | Sessions, ground truth, detections | Optional but required for controlled campaigns | No |
| `source.ip` | IP string | Source address of observed connection | Pi/Logstash | Search, campaign/session features | Yes | Operationally sensitive |
| `event.type` | enum string | Normalized event kind | Pi/Logstash | Rules, features, research | Yes | No |
| `event.action` | string | Action within the event kind | Pi/Logstash | Rules, UI | Optional | No |
| `device.id` | string | Honeypot device identifier | Pi | Search, features | Yes | No |
| `honeypot.name` | string | Honeypot implementation | Pi | Search, research | Yes | No |
| `attack.classification` | enum string | Detector/normalization classification | Logstash/rules | Rules, explainability | Optional; never assumed ground truth | No |
| `attack.stage` | enum string | Attack lifecycle stage | Rules/campaign logic | Campaign/session UI | Optional | No |
| `ground_truth_label` | string | Independent scenario/analyst/external label | Campaign/research annotation | Evaluation only | Optional | No |
| `ground_truth_source` | enum | Provenance of independent label | Campaign/research annotation | Evaluation/audit | Optional | No |
| `rule_prediction` | string | Rule detector output | Runtime rule detector | Hybrid fusion/UI | Optional | No |
| `classifier_prediction` | string | Supervised detector output | Runtime ML | Hybrid fusion/UI | Optional | No |
| `anomaly_prediction` | string | Anomaly detector output | Runtime ML | Hybrid fusion/UI | Optional | No |
| `final_prediction` | string | Explicit hybrid decision | Hybrid policy | Detections/UI | Optional | No |
| `detector` | enum | RULE, CLASSIFIER, ANOMALY, or HYBRID | Runtime detector | Detections/UI | Optional | No |
| `detector_version` | string | Detector implementation/model version | Runtime detector | Detections/research | Optional | No |
| `confidence` / `probability` | number | Classifier confidence where available | Runtime ML | Detections/UI | Optional | No |
| `anomaly_score` | number | Anomaly score where available | Runtime anomaly detector | Detections/UI | Optional | No |
| `decision_source` | string | Policy source for final decision | Hybrid detector | Detections/audit | Optional | No |
| `decision_reason` | string | Human-readable deterministic reason | Detector | Detections/UI | Optional; redact credentials | No |

## Scientific invariants

`RULE_PREDICTION != GROUND_TRUTH`; `NO_RULE != BENIGN`; `UNLABELED == UNKNOWN`; `SYNTHETIC != REAL_WORLD`. The dashboard renders stored backend fields and never manufactures lineage or labels.
