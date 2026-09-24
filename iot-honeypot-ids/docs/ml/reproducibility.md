# Reproducibility

## What every experiment records

Every call to `python -m model_lab.train|evaluate|compare` writes a JSON file
under `model-lab/experiments/` containing:

```json
{
  "experiment_id": "exp-<timestamp>",
  "model_id": "model-v001",
  "algorithm": "random_forest",
  "dataset_version": "v1",
  "feature_version": "v1",
  "seed": 42,
  "metrics": {
    "accuracy": 0.92,
    "precision_macro": 0.89,
    "recall_macro": 0.88,
    "f1_macro": 0.88,
    "confusion_matrix": [[...]],
    "per_class": {...}
  },
  "split": {
    "train_size": 168,
    "test_size": 42,
    "test_ratio": 0.2
  },
  "notes": "session-level held-out evaluation"
}
```

## Why this matters

- **Reproducibility**: anyone with the same `dataset_version`, `seed`, and
  hyperparameters gets the same model.
- **Auditability**: the FastAPI `/experiments` endpoint lists every
  experiment so you can see exactly what was tried.
- **Comparison**: `python -m model_lab.compare --model-ids model-v001 model-v002`
  shows you the metrics delta.

## Random seeds

The default seed is `42` (configurable via `--seed`). Every scikit-learn
estimator that supports `random_state` is given this seed, so:

- `train_test_split` is deterministic
- `RandomForestClassifier`'s bootstrap sampling is deterministic
- `IsolationForest`'s tree selection is deterministic

Same dataset + same seed + same hyperparameters = same model.

## Data versioning

Datasets live under `model-lab/datasets/<version>/sessions.csv`:

| Version | Source                                 | Notes                                |
|---------|----------------------------------------|--------------------------------------|
| v1      | `model_lab.datasets.bootstrap`         | Clearly SYNTHETIC                     |
| v2      | `model_lab.datasets.from_es`           | Real Elasticsearch events              |

Each model's metadata records which `dataset_version` it was trained on, so
experiments across dataset versions are clearly distinguishable.

## Model versioning

Models live under `model-lab/models/<id>/`:

```
model-v001/
├── model.joblib       # the trained estimator
├── scaler.joblib      # optional feature scaler
├── metadata.json      # algorithm, hyperparameters, metrics, seed, status
└── README.md          # human-readable summary
```

Never overwritten. Status transitions:

```
experimental -> validated -> active -> retired
```

`POST /models/{id}/status` on the FastAPI service moves a model between
statuses. Only one model should be `active` at a time (the runner uses the
latest `active` model for replay by default).
