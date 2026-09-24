# TRAPSIG Research Baseline

## Scope

This document freezes the implementation claims that are supportable from the repository. It does not claim physical deployment, latency, resource usage, or external-dataset results that were not measured.

## Architecture and topology

A Raspberry Pi runs Cowrie, camera, and IoT honeypots plus Filebeat and an optional collector. Filebeat sends telemetry over Beats/TCP to Logstash on a Fedora analysis host. Logstash normalizes events into Elasticsearch. FastAPI reads Elasticsearch and owns runtime sessions, detections, campaigns, model registry, and Pi control. The root Next.js console presents the backend state. The attacker tooling is a separate lab-constrained client.

## Data and ground truth

Events are grouped into sessions and campaigns. Controlled scenarios define intended behavior and provide `SCENARIO_GROUND_TRUTH`; analyst, external, synthetic, and unlabeled sources are represented separately. Rule, classifier, anomaly, and hybrid outputs are predictions and are never used as independent ground truth. Unlabeled is unknown, not benign.

## Features

Runtime feature extraction is in `dashboard/ml/features.py`. Feature version `v2` excludes the known leaky fields `contains_path_traversal`, `contains_command_injection`, and `contains_default_credentials` from leakage-safe classifier vectors. Feature provenance and online/offline availability must be recorded with experiment metadata. Full-session features are not automatically early-online measurements.

## Detection

RULE, SUPERVISED CLASSIFIER, and ANOMALY DETECTOR are separate detector types. Hybrid fusion is an explicit runtime policy. Detection records preserve detector identity/version, prediction, confidence or anomaly score where available, decision source/reason, and campaign/session/event lineage.

## Experiments and splits

The research pipeline is dataset validation, split selection, train-only preprocessing, fitting, model freezing, and held-out evaluation. Experiment metadata records dataset/version, feature version, split strategy, seed, algorithm, hyperparameters, and commit where available. Session, campaign, temporal, and scenario-level protocols are distinct; temporal splitting must not silently become random splitting.

## Reproducibility and security

Synthetic fixtures are labeled and separate from live telemetry. API mutations require a configured secret and attacker scenarios require an explicit target inside the configured lab subnet. Logs and API errors must not expose credentials or keys. Model activation is an explicit registry action; invalid historical artifacts remain invalid.

## Verification status

### Software verified

Source-level schema, label-provenance, leakage-audit, mode-boundary, model-registry, Pi-control, campaign, and E2E contract tests exist in the repository. Shell syntax and frontend/build/configuration checks are run where the environment permits.

### Physical lab verified

NOT VERIFIED. No commands were executed against a Raspberry Pi or Fedora analysis host during finalization.

### Measured results

No new physical latency, CPU, RAM, temperature, disk, network, ingestion-loss, or detection-performance measurements were produced during this finalization pass.

### Known limitations

The active environment is Python 3.14 while pinned scientific dependencies include versions that do not install cleanly there. Elasticsearch, Logstash, Kibana, Pi connectivity, and physical E2E therefore require a compatible deployment environment before they can be marked PASS.
