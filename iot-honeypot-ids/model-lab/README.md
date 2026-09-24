# Model Lab — ML research workspace

A reproducible ML pipeline for the IoT honeypot IDS.

## What lives here

| Folder          | Purpose                                                    |
|-----------------|------------------------------------------------------------|
| `datasets/`     | Versioned raw + processed session datasets (CSV / Parquet)  |
| `features/`     | Feature extraction scripts (mirror of `dashboard/ml/`)      |
| `training/`     | CLI entry point for training a model                        |
| `evaluation/`   | CLI entry point for evaluation / experiments               |
| `replay/`       | Replay harness — runs an attack then runs the model on it   |
| `experiments/`  | Per-experiment metadata (JSON files, one per experiment)   |
| `models/`       | Trained model artifacts (each in its own `model-vNNN/` dir) |

## CLI

The pipeline is exposed as a Python module:

```bash
python -m model_lab.train --algorithm random_forest --seed 42
python -m model_lab.evaluate --model-id model-v001
python -m model_lab.replay  --scenario ssh-bruteforce --target 192.168.1.50
python -m model_lab.compare --model-ids model-v001 model-v002
```

## Reproducibility

Every experiment records:

```
experiment_id, dataset_version, feature_version, algorithm, hyperparameters,
seed, training_timestamp, metrics, model_version
```

Models are never overwritten — each gets its own `model-vNNN/` directory
containing the artifact + metadata + README.

## Datasets

Datasets are stored as CSV files under `datasets/<version>/sessions.csv`
with one row per reconstructed session. Each row contains the v1 feature
vector plus a `label` column.

To bootstrap a dataset from synthetic data (clearly labeled):

```bash
python -m model_lab.datasets.bootstrap --out datasets/v1/sessions.csv
```

To build a dataset from real Elasticsearch data (requires PC1 to be up):

```bash
python -m model_lab.datasets.from_es --out datasets/v2/sessions.csv
```

## Avoiding data leakage

Splits happen at the **session level**, not the event level. Two events
from the same session never appear in both train and test. See
`dashboard/ml/evaluate.py:session_level_split`.
