# Experiments

Each `python -m model_lab.train|evaluate|compare` call writes a JSON file here:

```
exp-<timestamp>.json
```

Each file records:

```json
{
  "experiment_id": "exp-...",
  "model_id": "model-v001",
  "algorithm": "random_forest",
  "dataset_version": "v1",
  "feature_version": "v1",
  "seed": 42,
  "metrics": { ... },
  "notes": "..."
}
```

The FastAPI `/experiments` endpoint lists these files.
