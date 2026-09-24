# TRAPSIG Baseline Audit

## Architecture Map

### Computer 1: Raspberry Pi (Pi 4, 4GB RAM)
- **Cowrie** SSH/Telnet honeypot (port 2222/2223) — container `pi-cowrie`
- **Camera** HTTP honeypot (port 8080) — container `pi-camera`
- **IoT service** TCP honeypot (port 9000) — container `pi-iot-service`
- **Filebeat** (8.13.4) — ships JSONL logs to Logstash via TCP 5044
- **Collector** (optional) — local spool buffer for when Logstash is unreachable

### Computer 2: Fedora Analysis Server
- **Elasticsearch** (8.13.4) — single-node, stores honeypot-events/sessions/campaigns/detections/errors/training indices
- **Logstash** (8.13.4) — receives Beats, normalizes to ECS, routes malformed to dead-letter
- **Kibana** (8.13.4) — raw telemetry analyst view
- **FastAPI** — dashboard API: sessions, campaigns, detections, models, experiments
- **Next.js dashboard** — SOC console UI with Overview/Honeypots/Events/Sessions/Detections/Models pages
- **model-lab** — ML training/evaluation/research framework
- **Attacker simulator** — Python safety-first attack harness (`attacker/trapsig_attack.py`)

### Computer 3: Attacker (optional)
- Python attack simulator with safety layer (CIDR/port/scenario allowlists)
- Writes experiment manifests as ground truth

## Data Flow Map

```
Pi honeypots → JSONL log files → Filebeat → Logstash (TCP 5044)
  → normalize ECS fields → Elasticsearch (honeypot-events-*)
  → session materializer (15s scheduler) → honeypot-sessions-*
  → campaign correlator → honeypot-campaigns-*
  → feature extractor (v2, leak-free)
  → rule detector / anomaly detector / hybrid detector
  → honeypot-detections-*
  → FastAPI → Next.js dashboard
```

## Training Flow Map

```
Dataset CSV → ExperimentRunner
  → validate provenance (LabelSource enum)
  → validate features (leakage audit: SAFE/SUSPECT/LEAKY)
  → split BEFORE training (SESSION_LEVEL / CAMPAIGN / TEMPORAL / HONEYPOT)
  → FREEZE test set (train/test session ID disjoint check)
  → train ONLY on train data (fit scaler on train only)
  → evaluate ONLY on test data
  → compute metrics (macro F1, precision, recall, FPR, FNR, confusion matrix)
  → record experiment_id, git_commit, environment, seed, split, train/test IDs
  → mark VALID or INVALID
```

## Detection Flow Map

```
Session → features (v2)
  → Rule detector (5 rules, confidence ≥ 0.85 = strong)
  → Supervised classifier (if active + schema compatible, prob ≥ 0.7 = strong)
  → Anomaly detector (if trained, score < threshold = anomaly)
  → Hybrid fusion (contributed_signals list, no fabrication on NO_SIGNAL)
  → Detection persisted (detector_config_fingerprint, model_id, model_version)
  → Lineage: detection → session → events → features → campaign → model
```

## Ground-Truth Flow

```
Controlled campaign → manifest.json (campaign_id, scenario, intended_label)
  → ground_truth_source = SCENARIO_GROUND_TRUTH
  → ground_truth_label = campaign's intended label
  → SEPARATE from rule_prediction / classifier_prediction / anomaly_prediction

Rule engine output → rule_prediction (NOT ground truth)
"No rule fired" → label = "unknown" (NOT "benign")
"Benign" only when BENIGN campaign explicitly establishes it
```

## Current Failure Points (Previously Fixed)

| # | Issue | Status |
|---|---|---|
| C1 | Train-on-all-data then evaluate on split | FIXED — ExperimentRunner splits before training |
| C2 | Rule output used as ground truth label | FIXED — LabelSource enum + from_es.py separation |
| C3 | "No rule fired" = "benign" | FIXED — "unknown" for unlabeled traffic |
| C4 | Feature leakage (3 features from attack.classification) | FIXED — leakage_audit.py rejects LEAKY features |
| C5 | Filebeat queue.spool incompatible with 8.13.4 | FIXED — queue.disk |
| C6 | Collector data not mounted into Filebeat | FIXED — collector_data:/var/log/collector:ro |

## Current Tests

| Test File | Tests | Coverage |
|---|---|---|
| test_scientific_integrity.py | 28 | Label provenance, leakage audit |
| test_experiment_validity.py | 14 | Train/test isolation, experiment validity |
| test_pass7_hardening.py | 121 | Campaign lifecycle, detection ID, temporal split |
| test_pass7_pipeline.py | 68 | Campaign correlation, feature extraction, detectors |
| test_pass5_*.py | ~200 | Runtime mode, session materialization, telemetry |
| test_pass4_*.py | ~40 | Pi control plane |
| test_attacker_safety.py | 10 | Attacker safety checks |
| Other unit tests | ~90 | Features, rules, datasets, models |

## Reproducibility Mechanisms

| Mechanism | Status |
|---|---|
| Experiment ID (deterministic from spec) | Implemented |
| Git commit recording | Implemented |
| Environment capture (Python/sklearn/numpy) | Implemented |
| Seed recording | Implemented |
| Train/test ID persistence | Implemented |
| Split protocol recording | Implemented |
| Feature version recording | Implemented |
| Label source recording | Implemented |
| Multi-seed evaluation (42, 123, 456, 789, 1337) | Implemented |
| Legacy experiment quarantine (INVALID) | Implemented |

## Component Status Table

| Component | Current behavior | Scientific risk | Engineering risk | Required action |
|---|---|---|---|---|
| train.py | Trains on all data (legacy path) | HIGH — invalid evaluation | LOW — deprecated by ExperimentRunner | Mark as deprecated, warn on use |
| evaluate.py | Splits then evaluates pre-trained model | HIGH — invalid held-out | LOW — deprecated by ExperimentRunner | Mark as deprecated |
| ExperimentRunner | Splits before training, validates provenance | NONE — correct | LOW | None |
| from_es.py | Separates ground_truth from rule_prediction | NONE — fixed | LOW | None |
| features.py | v1 has 3 leaky features, v2 excludes them | LOW — v2 is default | LOW | None |
| rules.py | 5 deterministic rules | NONE | LOW | Independent evaluation pending real data |
| models.py | RF/LR/GB/IF training | NONE | LOW | None |
| Filebeat | queue.disk (8.13.4 compatible) | NONE — fixed | LOW | Physical test pending |
| Collector | Mounted into Filebeat | NONE — fixed | LOW | Physical test pending |
| Logstash | Normalizes ECS, routes malformed | NONE | LOW | Physical test pending |
| ExperimentRunner | Proper train/test isolation | NONE — correct | LOW | None |
| LabelProvenance | Formal enum, rejects RULE_ENGINE as ground truth | NONE — correct | LOW | None |
| LeakageAudit | SAFE/SUSPECT/LEAKY classification | NONE — correct | LOW | Full feature registry pending |
| Hybrid fusion | Explicit policy, config fingerprint | NONE — correct | LOW | Ablation study pending real data |
| Campaign framework | research/ directory + hypotheses | NONE | LOW | Campaign manifests pending real data |
| Attacker simulator | Safety-first, dry-run, manifests | NONE | LOW | Physical test pending |
| Dashboard | Next.js, real API data | NONE | LOW | Research mode separation pending |

## Verification Gate

BASELINE_AUDIT = PASS
