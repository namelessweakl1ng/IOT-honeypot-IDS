# Ground Truth Specification

## Overview

TRAPSIG separates ground truth from detector predictions. A detector output
(rule engine, classifier, anomaly detector) is NEVER automatically treated
as ground truth. Ground truth comes from independent sources.

## Label Source Hierarchy

| Source | is_ground_truth | Description |
|---|---|---|
| SCENARIO_GROUND_TRUTH | YES | Controlled attacker campaign manifest (highest reliability) |
| ANALYST_LABELED | YES | Human analyst annotation |
| EXTERNAL_DATASET | YES | Labels from IoT-23, N-BaIoT, or other external datasets |
| SYNTHETIC | DEVELOPMENT FIXTURE ONLY | Generated labels may exercise software behavior; experiments using them are INVALID as research evidence and cannot produce a research-active model |
| RULE_ENGINE | **NO** | Rule detector output — a PREDICTION, not ground truth |
| UNLABELED | **NO** | No label available — remains UNKNOWN |

## Critical Invariants

1. `rule_prediction` can NEVER populate `ground_truth_label`
2. "No rule fired" → `label = "unknown"` (NOT "benign")
3. "Benign" only when a BENIGN campaign explicitly establishes it
4. RULE_ENGINE confidence capped at 0.9 (detector output, not certainty)
5. `validate_label_for_training()` RAISES if label_source=RULE_ENGINE

## Dataset Schema (from_es.py output)

Each dataset row contains:

| Field | Description |
|---|---|
| `session_id` | Unique session identifier |
| `label` | Dataset label (may be "unknown" for unlabeled traffic) |
| `label_source` | How the label was derived (enum above) |
| `ground_truth_label` | Independent ground truth (None if unavailable) |
| `ground_truth_source` | Source of ground truth (None if unavailable) |
| `rule_prediction` | Rule engine output (a PREDICTION, not ground truth) |
| `rule_id` | Which rule fired (e.g. rule_brute_force_v1) |
| `rule_confidence` | Rule confidence (0.0-1.0) |
| `campaign_id` | Campaign this session belongs to (if known) |
| `scenario_id` | Scenario type (if known) |
| `dataset_version` | Dataset version string |
| `created_at` | Session creation timestamp |
| features... | v2 leak-free behavioral features |

## Label Decision Logic (from_es.py)

```
if label_source == SCENARIO:
    label = rule_label or "unknown"
    ground_truth_label = rule_label  # verified against campaign manifest
    ground_truth_source = "SCENARIO"

elif label_source == ANALYST:
    label = rule_label or "unknown"
    ground_truth_label = rule_label
    ground_truth_source = "ANALYST"

elif label_source == UNLABELED:
    label = "unknown"          # NOT "benign"
    ground_truth_label = None
    ground_truth_source = "UNLABELED"

elif label_source == RULE_ENGINE:
    label = rule_label or "unknown"
    ground_truth_label = None  # NEVER set ground truth from rules
    ground_truth_source = "RULE_ENGINE"
```

## Campaign Ground Truth

For controlled campaigns:

```
campaign manifest:
  campaign_id: campaign-20260912-001
  scenario: ssh-bruteforce
  intended_label: brute_force
  ground_truth_source: SCENARIO_GROUND_TRUTH

→ every session from this campaign gets:
  ground_truth_label = "brute_force"
  ground_truth_source = "SCENARIO_GROUND_TRUTH"
  label_source = "SCENARIO"
```

For benign campaigns:

```
campaign manifest:
  campaign_id: campaign-20260912-benign-001
  scenario: benign_http
  intended_label: benign
  ground_truth_source: SCENARIO_GROUND_TRUTH

→ every session from this campaign gets:
  ground_truth_label = "benign"
  ground_truth_source = "SCENARIO_GROUND_TRUTH"
  label_source = "SCENARIO"
```
