# Hybrid Detection Fusion Policy

## Overview

TRAPSIG uses a three-tier hybrid detection architecture:

- **Tier 1**: Deterministic rule engine (5 rules)
- **Tier 2**: Supervised classifier (RandomForest / LogisticRegression / GradientBoosting)
- **Tier 3**: Anomaly detector (IsolationForest)

This document defines the EXACT fusion policy that combines these tiers
into a final detection decision.

## Formal Decision Policy

### Input

```
session: SessionDocument
  → features: v2 feature vector
  → events: chronological event list
```

### Step 1: Evaluate Deterministic Rules

```
rule_result = rule_detector.detect_for_session(session_id)
  → rule_id, label, confidence, severity
  → or None if no rule fires
```

Rules are evaluated FIRST because they are deterministic and fast.
If a rule fires with confidence ≥ RULE_CONFIDENCE_THRESHOLD (0.85),
it is a "strong" signal.

### Step 2: Evaluate Supervised Classifier

```
classifier_result = supervised_model.predict(features)
  → label, probability, model_id, model_version
  → or None if no active model or schema mismatch
```

The classifier is only evaluated if:
- A model is active (status=active in model registry)
- The model's feature_version matches the runtime FEATURE_SCHEMA_VERSION
- The model has been validated (status=validated → active)

If classifier probability ≥ SUPERVISED_PROBABILITY_THRESHOLD (0.7),
it is a "strong" signal.

### Step 3: Evaluate Anomaly Detector

```
anomaly_result = anomaly_detector.score_session(features)
  → anomaly_score, threshold, is_anomaly
  → or None if detector not trained
```

The anomaly detector is only evaluated if it has been trained
(POST /anomaly/train was called). The threshold was calibrated
on validation data (research mode) or same-data (operational mode).

### Step 4: Apply Fusion Policy

```
contributed_signals = []

if rule_result and rule_result.confidence >= RULE_CONFIDENCE_THRESHOLD:
    contributed_signals.append("rule_engine")

if classifier_result and classifier_result.probability >= SUPERVISED_PROBABILITY_THRESHOLD:
    contributed_signals.append("supervised_model")

if anomaly_result and anomaly_result.is_anomaly:
    contributed_signals.append("anomaly_detector")

if not contributed_signals:
    return None  # NO_SIGNAL — no detection (no fabrication)
```

### Step 5: Determine Final Label + Severity

```
if "rule_engine" in contributed_signals:
    label = rule_result.label  # rules take priority for known attacks
    severity = rule_result.severity
elif "supervised_model" in contributed_signals:
    label = classifier_result.label
    severity = "high"
elif "anomaly_detector" in contributed_signals:
    label = "anomaly"  # anomaly is a SIGNAL, not a malicious verdict
    severity = "medium"

if len(contributed_signals) >= 2:
    severity = "high"  # multiple independent signals agreeing
```

### Step 6: Produce Detection Decision Record

```
detection = {
    detection_id: hash(session_id + contributed_signals + config_fingerprint),
    session_id,
    campaign_id,
    final_label: label,
    decision_source: "hybrid",
    detector_version: "hybrid_v1",
    rule_result: {rule_id, label, confidence} or None,
    classifier_result: {label, probability, model_id} or None,
    anomaly_result: {anomaly_score, threshold, is_anomaly} or None,
    contributed_signals: [...],
    confidence: max(rule_confidence, classifier_probability),
    anomaly_score: anomaly_result.score or None,
    threshold: anomaly_result.threshold or None,
    feature_version: "v2",
    model_id: classifier_result.model_id or None,
    model_version: classifier_result.model_version or None,
    rule_version: rule_result.rule_id or None,
    explanation: "rule_engine: rule_brute_force_v1 (brute_force, conf=0.90) | ...",
    thresholds: {
        rule_confidence_threshold: 0.85,
        supervised_probability_threshold: 0.7,
        anomaly_threshold: anomaly_result.threshold or None,
    },
    persisted: bool,
    timestamp: ISO-8601,
}
```

## Pseudocode

```python
def evaluate_session(session_id):
    session = load_session(session_id)
    if not session:
        return None

    # Tier 1: Rules
    rule_result = rule_detector.detect_for_session(session_id)
    if rule_result and rule_result.confidence >= 0.85:
        contributed.append("rule_engine")

    # Tier 2: Supervised (if active + schema-compatible)
    classifier_result = run_supervised(session_id)
    if classifier_result and classifier_result.probability >= 0.7:
        contributed.append("supervised_model")

    # Tier 3: Anomaly (if trained)
    anomaly_result = anomaly_detector.detect_for_session(session_id)
    if anomaly_result and anomaly_result.is_anomaly:
        contributed.append("anomaly_detector")

    # Fusion
    if not contributed:
        return None  # NO_SIGNAL

    label = determine_label(contributed, rule_result, classifier_result, anomaly_result)
    severity = determine_severity(contributed, rule_result)

    detection = build_detection_record(
        session_id, contributed, label, severity,
        rule_result, classifier_result, anomaly_result
    )
    persist_detection(detection)
    return detection
```

## Runtime vs Research Hybrid

### Runtime Hybrid (dashboard / live detection)
- **Inputs**: rules + supervised + anomaly
- **Rule evidence**: available (real honeypot events with attack.classification)
- **Use**: operational detection + alerting

### Research Feature Hybrid (model-lab experiments)
- **Inputs**: supervised + anomaly (NO rule engine)
- **Rule evidence**: NOT available in external datasets (IoT-23, N-BaIoT)
- **Use**: controlled research evaluation
- **Note**: the research HybridDetector in `model-lab/model_lab/research.py`
  does NOT include the rule engine because external datasets lack
  event-level rule evidence. Forcing rules into incompatible datasets
  would create fake features.

## Thresholds

| Threshold | Value | Rationale |
|---|---|---|
| `RULE_CONFIDENCE_THRESHOLD` | 0.85 | Rules at ≥0.85 confidence are "strong" — they alone justify a KNOWN_ATTACK detection. Below 0.85, rules contribute as weak evidence. |
| `SUPERVISED_PROBABILITY_THRESHOLD` | 0.7 | Classifier predictions at ≥0.7 probability are "strong". Below 0.7, supervised contributes as weak evidence. The runtime threshold (0.7) is higher than the research threshold (~0.5) because operational false positives are more costly than research evaluation errors. |
| `anomaly_threshold` | calibrated | Selected on validation data (research) or same-data (operational). NEVER hardcoded. The calibration method + target FPR are recorded in the detection. |

## Design Principles

1. **No fabrication**: if no signal fires, no detection is created.
2. **Provenance preserved**: `contributed_signals` lists which tiers fired.
3. **Anomaly ≠ malicious**: anomaly is a SIGNAL that contributes to the
   hybrid decision. It is NOT collapsed into a malicious verdict.
4. **Rules priority**: for known attacks, rules take label priority over
   the classifier (rules are deterministic ground truth for known patterns).
5. **Config fingerprint**: the detection_id includes the config fingerprint
   so config changes produce different detection_ids (no historical overwrite).
6. **Detector ≠ model**: `detector_version` (hybrid_v1) is distinct from
   `model_id`/`model_version` (the registered ML model that contributed).
