# TRAPSIG Scientific Validity Audit

## Overview

This audit was performed before implementing research-hardening changes.
It documents every scientific validity issue found in the repository
and classifies them by severity.

## CRITICAL Issues

### C1: Invalid held-out evaluation (train-on-all-data)
**Severity**: CRITICAL
**Status**: FIXED (commit c7211ba)

**Finding**: `train.py` trained the model on ALL 210 synthetic samples.
`evaluate.py` later created an 80/20 session split and evaluated the
already-trained model on the test portion. The model saw test data during
fitting, making the reported F1=1.00 an invalid estimate of generalization.

**Fix**: Implemented `ExperimentRunner` that splits BEFORE training.
The test set is frozen and never enters `fit()`. Legacy experiments
marked `status=INVALID` with explicit reason.

### C2: Rule-derived labels used as ground truth
**Severity**: CRITICAL
**Status**: FIXED (commits ae1d911 + this commit)

**Finding**: `from_es.py` line 103: `label = rule["label"] if rule else "benign"`
This uses rule engine output as the dataset label — circular evaluation.
Additionally, "no rule fired" was treated as "benign", but absence of
detection does NOT prove benign traffic.

**Fix**:
- Implemented `LabelSource` enum (SCENARIO_GROUND_TRUTH, ANALYST_LABELED,
  EXTERNAL_DATASET, SYNTHETIC, RULE_ENGINE, UNLABELED)
- `validate_label_for_training()` rejects RULE_ENGINE labels as ground truth
- `from_es.py` now separates: `ground_truth_label`, `ground_truth_source`,
  `rule_prediction`, `rule_id`, `rule_confidence`
- "No rule fired" → `label="unknown"` (not "benign") for unlabeled traffic
- "Benign" only used when a BENIGN campaign explicitly establishes it

### C3: Feature leakage
**Severity**: CRITICAL
**Status**: FIXED (commit ae1d911)

**Finding**: `features.py` includes `contains_path_traversal`,
`contains_command_injection`, `contains_default_credentials` — derived
from `attack.classification` (Logstash enrichment). Using these in
classifier training creates circular evaluation.

**Fix**: Implemented `leakage_audit.py` with SAFE/SUSPECT/LEAKY/UNKNOWN
classification. `ExperimentRunner` rejects LEAKY features unless
`allow_leaky=True` (experimental leakage analysis mode).

### C4: Filebeat queue.spool incompatibility
**Severity**: CRITICAL
**Status**: FIXED (commit ae1d911)

**Finding**: `pi/filebeat/filebeat.yml` used `queue.spool` which
Filebeat 8.13.4 rejects: "unrecognized queue type 'spool'". This
broke telemetry forwarding.

**Fix**: Replaced with `queue: type: disk` (supported by Filebeat 8.13.4).
Bounded by `max_size: 100MB` to prevent Pi SD card fill.

### C5: Collector reliability path broken
**Severity**: CRITICAL
**Status**: FIXED (this commit)

**Finding**: The collector writes buffered files to `collector_data:/data`,
but Filebeat did NOT mount `collector_data`. The collector's spool files
were never consumed — the "reliability" it claimed was not real.

**Fix**: Mounted `collector_data:/var/log/collector:ro` into Filebeat.
Filebeat can now consume the collector's spool files. Filebeat's own
disk queue (`queue.disk`) provides the PRIMARY durability guarantee.
The collector is an OPTIONAL supplementary buffer.

## HIGH Issues

### H1: No experiment immutability
**Severity**: HIGH
**Status**: FIXED (commit c7211ba)

Experiments could be silently overwritten. The `ExperimentRunner` now
generates a deterministic `experiment_id` from spec parameters and
writes results as immutable artifacts.

### H2: No environment capture for reproducibility
**Severity**: HIGH
**Status**: FIXED (commit c7211ba)

`ExperimentRunner` captures: git_commit, python_version, platform,
architecture, numpy/pandas/sklearn versions.

### H3: No multi-seed evaluation
**Severity**: HIGH
**Status**: FIXED (commit c7211ba)

`run_multi_seed()` with default seeds [42, 123, 456, 789, 1337].
`aggregate_results()` produces mean ± std for each metric.

## MEDIUM Issues

### M1: No formal hybrid fusion policy
**Severity**: MEDIUM
**Status**: FIXED (commit ae1d911)

Documented at `docs/ml/hybrid-decision.md` with pseudocode.

### M2: No research artifact directory
**Severity**: MEDIUM
**Status**: FIXED (commit ae1d911)

Created `research/` with campaigns/, datasets/, experiments/, reports/,
figures/, tables/, manifests/. Added `hypotheses.yaml` with RQ1-RQ8.

## LOW Issues

### L1: No dataset audit command
**Severity**: LOW
**Status**: FIXED (commit ae1d911)

Created `scripts/research/audit_dataset.py`.

## NOT YET FIXED

The following issues require physical lab execution or additional
implementation phases:

- Real Pi data collection (requires hardware)
- IoT-23 / N-BaIoT adapter validation (requires datasets)
- Rule engine independent evaluation (requires ground truth data)
- Hybrid ablation study (requires experiment results)
- Isolation Forest threshold analysis (requires experiment results)
- Cross-honeypot generalization (requires multi-honeypot data)
- Resource/latency/throughput measurement (requires physical Pi)
- Paper table/figure generation (requires experiment results)
- False positive study (requires benign campaign data)
- Robustness/evasion testing (requires variant data)
