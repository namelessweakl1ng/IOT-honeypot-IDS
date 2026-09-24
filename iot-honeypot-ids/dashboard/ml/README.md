# ML pipeline — shared library

Pure-Python ML code used by both the FastAPI service and the `model-lab`
CLI. Three logical modules:

| Module        | Purpose                                                |
|---------------|--------------------------------------------------------|
| `features.py` | Session reconstruction + behavioral feature extraction |
| `models.py`   | Train classifiers / anomaly detectors                  |
| `evaluate.py` | Cross-validated metrics + per-class reports            |
| `registry.py` | Wrapper around the API's model registry (filesystem)   |

The pipeline is intentionally small and explainable:

1. Pull sessions from Elasticsearch
2. Reconstruct each session into a feature vector
3. Split at the **session** level (never at the event level — no leakage)
4. Train one of: LogisticRegression, RandomForest, GradientBoosting, IsolationForest
5. Evaluate with accuracy/precision/recall/F1 + confusion matrix + ROC-AUC where applicable
6. Persist the model artifact + metadata under `model-lab/models/<id>/`
