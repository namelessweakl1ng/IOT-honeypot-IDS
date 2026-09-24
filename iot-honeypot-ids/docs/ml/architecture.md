# ML documentation

## Architecture

```
                    EVENT SESSION
                         |
              +----------+----------+
              |                     |
         Rule Engine            ML Engine
         (deterministic)         |
                          +------+------+
                          |             |
                     classifier    anomaly detector
                     (Random Forest,   (Isolation Forest,
                      LogReg, GB)       One-Class SVM)
```

- **Rules** handle obvious deterministic patterns (path traversal in URI,
  default creds, brute force signature). They emit high-confidence labels.
- **Classifier** handles known attack classes learned from labeled sessions.
- **Anomaly detector** flags sessions that don't match the training
  distribution (no label needed).

See also [`shared/documentation/design-decisions.md`](../../shared/documentation/design-decisions.md).

## Features

The v1 feature vector has 25 dimensions, documented in
[`dashboard/ml/features.py`](../../dashboard/ml/features.py). Highlights:

| Feature                          | Why it matters                                  |
|----------------------------------|--------------------------------------------------|
| `event_count`                    | Sessions with many events are usually suspicious |
| `auth_failure_ratio`             | Brute force signature                            |
| `unique_usernames`               | Brute force signature                            |
| `http_uri_diversity`             | Recon signature                                   |
| `contains_path_traversal`        | Path traversal signature                         |
| `contains_command_injection`     | RCE signature                                     |
| `contains_default_credentials`   | Default creds signature                          |
| `time_between_events_mean_s`     | Bot-like pacing                                   |
| `request_rate_per_min`           | High rate = likely automated                      |

See [`features.md`](features.md) for the full list + rationale.

## Algorithms supported

| Algorithm            | Type        | Why we use it                                  |
|----------------------|-------------|------------------------------------------------|
| `logistic_regression` | classifier | Linear baseline, fast, explainable via coefficients |
| `random_forest`      | classifier  | Robust nonlinear, gives feature importances    |
| `gradient_boosting`  | classifier  | Often best raw accuracy on tabular data         |
| `isolation_forest`   | anomaly     | Standard unsupervised anomaly detector          |

## Training pipeline

```
raw events
    ↓
session reconstruction       (group events by session_id)
    ↓
feature extraction           (features.extract_features)
    ↓
data validation              (drop sessions with < 1 event)
    ↓
labeling                     (rule engine first, manual labels second)
    ↓
dataset version              (datasets/v1/sessions.csv, etc.)
    ↓
train/validation/test split   (session_level_split — NO LEAKAGE)
    ↓
training                     (dashboard/ml/models.train)
    ↓
evaluation                   (dashboard/ml/evaluate.evaluate_classification)
    ↓
model artifact               (model-lab/models/model-vNNN/model.joblib)
    ↓
model metadata               (model-lab/models/model-vNNN/metadata.json)
```

## Reproducibility

Every experiment records:

```
experiment_id, dataset_version, feature_version, algorithm, hyperparameters,
seed, training_timestamp, metrics, model_version
```

See [`reproducibility.md`](reproducibility.md).

## Avoiding data leakage

Splits happen at the **session** level, not the event level. Two events
from the same session can never appear in both train and test. See
[`dashboard/ml/evaluate.py:session_level_split`](../../dashboard/ml/evaluate.py).

## Unknown attack experiment

```
KNOWN TRAINING DATA
        |
        v
      MODEL
        |
        v
UNSEEN ATTACK
        |
        v
ANOMALY SCORE
        |
        v
UNKNOWN / SUSPICIOUS
```

To run this experiment:

1. Train a model on a dataset that does **not** include a particular attack
   class (e.g., train without `command_injection`).
2. Run the `http-enumeration` scenario against the lab.
3. Use `python -m model_lab.replay --scenario http-enumeration --model-id <id>`
   to pull the resulting session and run the model on it.
4. The IsolationForest (or classifier with low confidence) flags the session
   as `anomaly` or `unknown`.
5. Label the session, add it to a new dataset version, retrain, evaluate.

## Model versioning

Models live under `model-lab/models/<id>/`:

```
model-v001/
├── model.joblib
├── scaler.joblib     (if applicable)
├── metadata.json
└── README.md
```

Never overwrite. Statuses: `experimental → validated → active → retired`.

## Evaluation metrics

```
accuracy
precision (macro)
recall (macro)
F1 (macro)
false-positive rate (macro)
false-negative rate (macro)
confusion matrix
per-class report
ROC-AUC (where applicable, binary or multiclass one-vs-rest)
PR-AUC (where applicable)
unknown/anomaly detection performance
```

If the dataset is too small to compute a metric honestly, the platform
returns `INSUFFICIENT DATA` instead of fabricating a number.
