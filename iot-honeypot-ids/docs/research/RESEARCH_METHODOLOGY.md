# Research methodology and status

## Questions and benchmarks

1. How does a flow-level classifier distinguish the published IoT-23 behavior labels under a scenario-held-out protocol? **Not yet evaluated.**
2. Can TRAPSIG ingest and trace controlled campaigns against the physical Pi honeypot through the API? **Physical validation NOT RUN.**

Benchmark A uses only the external IoT-23 dataset. Benchmark B uses only campaign records with campaign/scenario ground truth. The two datasets are not merged.

## Data, platform, and ground truth

IoT-23 is Zeek network-flow data labeled through the dataset authors' analysis workflow; normalized rows use `label_source=EXTERNAL_DATASET`. Controlled campaigns use `ground_truth_source=SCENARIO_GROUND_TRUTH`; detector outputs are predictions and never labels. Synthetic fixtures use `SYNTHETIC` and the experiment runner rejects them for research use. The intended hardware topology is Raspberry Pi sensor, Linux analysis host for ELK/FastAPI, and a dedicated attacker host. Physical versions and actual resource measurements are NOT RUN / NOT RECORDED here.

## Features and methods

The IoT-23 compatibility contract restricts the common flow feature view to measured duration, directional bytes, and directional packet counts. Flow identities, source paths, labels, label-derived values, scenario IDs, addresses, ports, protocol, and timestamps are metadata or excluded in the conservative cross-scenario view. Pi feature extraction remains session-based and must not be represented as equivalent to those flow measurements.

The project runtime has rule, supervised, anomaly, and hybrid paths. IoT-23 supports a separately evaluated classifier/anomaly path only when appropriate. Pi-specific rules do not apply to public flow data by default. Candidate classifier families are Logistic Regression, Random Forest, and Gradient Boosting; anomaly detection is a separate task with its own assumptions. No selected models, thresholds, or results are reported by this document.

## Splits, metrics, and reproducibility

Hold out whole IoT-23 scenarios into train/validation/test, with zero scenario overlap. A temporal split may be added only within captures for which chronology and the research question support it. Leave-one-scenario-out can be reported as a separate generalization analysis. Fit preprocessing on training data only. Do not tune on the final test set. Report per-class precision/recall/F1, macro F1, confusion matrix, FPR/FNR, and accuracy; add balanced accuracy and ROC/PR-AUC only when class support and score semantics permit. Record data and code hashes, split membership, algorithm, seed, feature version, environment, and git commit.

The current preparation adapter emits provenance and flow-level audit files. The scenario-split helper is deterministic and checks overlap. Actual dataset download, benchmark training, test evaluation, and result artifacts remain NOT RUN until a real copy is prepared and the experiment is executed. No synthetic fixture performance is research evidence.

## Threat model and limitations

The system studies hostile interactions directed at intentionally exposed lab honeypots and public IoT malware flow captures. Attacker activity stays in an isolated, authorized lab. Dataset labels may be incomplete or noisy; captures are historically and scenariowise limited. An anomaly score does not prove zero-day exploitation. Public dataset performance does not prove production deployment performance. Controlled lab attacks do not represent the whole Internet. Resource/latency claims need timestamped physical measurements and remain NOT RUN.
