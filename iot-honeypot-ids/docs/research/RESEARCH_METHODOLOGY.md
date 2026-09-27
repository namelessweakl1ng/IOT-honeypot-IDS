# Research methodology

## Research questions

1. **RQ1 — ingestion and reconstruction:** can controlled activity produce indexed events linked to sessions and campaigns? Evaluate only with `CONTROLLED_LAB` campaign records and event/session/campaign IDs.
2. **RQ2 — public flow classification:** how do Logistic Regression, Random Forest, and Gradient Boosting classify IoT-23 behavior labels on a held-out test scenario set? `PUBLIC_DATASET` only.
3. **RQ3 — flow anomaly scoring:** how does an Isolation Forest fit on benign training flows score held-out benign and malicious IoT-23 flows? External labels remain the evaluation reference; an anomaly score is not a TRAPSIG ground-truth label.
4. **RQ4 — operational cost:** what Pi host/container resources and stage timestamps occur during a declared controlled workload? `CONTROLLED_LAB` only.

These questions correspond to present tools. Campaign ablation or universal cross-dataset transfer is not claimed as implemented by the current runner.

## Data categories and provenance

- **PUBLIC_DATASET:** IoT-23 flow rows from the cited external source. `label_source=EXTERNAL_DATASET`; provenance detail states that labels are analyst-derived external annotations. Original labels, detailed labels, project taxonomy, scenario IDs, timestamp, and source-file provenance remain separate.
- **CONTROLLED_LAB:** actual Pi honeypot telemetry and attacker-run summary. A scenario manifest provides `ground_truth_source=SCENARIO_GROUND_TRUTH`; rule, classifier, anomaly, and hybrid output are predictions.
- **LIVE_TELEMETRY:** observations returned from currently configured backend services. LIVE is a runtime mode, not a ground-truth label and not proof of a physical experiment.
- **SYNTHETIC:** explicit fixtures under `examples/demo/` and test fixtures. They are not permitted in research experiments or physical-evidence claims.

IoT-23 network flows and Pi honeypot sessions are not merged into one dataset. They differ in granularity, features, capture protocol, and label source.

## IoT-23 validation, labels, and features

The importer reads `#fields` from each `conn.log.labeled`, preserves native labels and scenario IDs, normalizes Zeek epoch timestamps to UTC, and leaves absent numeric counters null. `validate_iot23` checks row shape, provenance category, timestamp validity, expected 23 scenarios, duplicate record IDs, exact measured-flow duplicate count, source importer rejection count, and label/missingness distributions. Structural corruption returns nonzero.

`iot23-flow-v1` uses duration, originator/responder bytes, and originator/responder packet counts. Preprocessing imputation/scaling is inside the scikit-learn pipeline and is fit only on training flows. IDs, scenario names, IPs, ports, protocol, labels, label-derived behavior fields, file paths, and timestamps are metadata or excluded. The detailed mapping is documented in `datasets/IOT23_FEATURE_MAPPING.md`.

## Splits and models

- **SCENARIO_HOLDOUT** is the principal protocol: whole scenarios are partitioned into train/validation/test, with zero scenario intersection. The split is deterministic for a fixed seed and sorted scenario inventory.
- **TEMPORAL_SPLIT** chronologically partitions timestamped rows. Scenario overlap is expected, so this protocol does not support a claim of unseen-scenario generalization. State this limitation with every result.
- A seeded per-scenario reservoir cap bounds memory; seen and retained counts are part of artifacts. Unmapped project labels are excluded and counted; they are never imputed from scenario names.
- Logistic Regression, Random Forest, and Gradient Boosting are supervised alternatives. Isolation Forest is fit only on benign training flows and evaluated against external binary labels. It reports an anomaly score and is not automatically a malicious verdict.
- Runtime Pi rules/classifier/anomaly/hybrid operate on reconstructed honeypot sessions. A rule prediction remains `RULE_PREDICTION`; detector output never becomes ground truth.

The runner performs **validate → split → fit preprocessing on train → fit model → save/freeze artifact → evaluate validation descriptively → evaluate test once**. It performs no hyperparameter tuning. The test partition is not used to select a model or threshold.

## Metrics and artifacts

Report accuracy, balanced accuracy, macro and per-class precision/recall/F1, binary FPR/FNR, and confusion matrices from actual predictions. Report PR-AUC/ROC-AUC only when score semantics and test class support make them defined; otherwise artifact value is null. Do not copy values into documentation as defaults.

Each experiment directory writes manifest, dataset, split, model metadata, metrics, predictions, confusion matrix, environment, README, and serialized model. Each artifact is wrapped with experiment context including ID, category, dataset/version/hash, label source, feature version, algorithm/parameters, seed, split, row counts, validity, code commit, and creation time.

## Physical measurements

Resource samples and T0-T9 timestamp captures are `CONTROLLED_LAB`. CPU, memory, temperature, load, disk, network and Docker statistics are collected as actual readings. The latency recorder leaves missing timestamps as `NOT MEASURED` and computes cross-host durations only when clock synchronization is declared verified. The physical demo and measured experiments have NOT RUN in this environment.

## Limitations

IoT-23 is historically and scenario limited, imbalanced, and analyst labeled; flows within captures are correlated. The scenario split reduces capture leakage but does not guarantee broad IoT generalization. The temporal split can include the same scenario on both sides. Network-flow results do not validate honeypot/session detection. Anomaly detection does not establish zero-day discovery. Controlled honeypot campaigns do not represent the whole Internet. No physical resource, latency, or end-to-end results are claimed before their actual execution.
