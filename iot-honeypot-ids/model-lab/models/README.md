# Model Registry

Fresh installation: NO active model.

## Legacy/Demo Models

The `legacy-demo/` directory contains models trained on the synthetic
bootstrap dataset. These are NOT research evidence.

- `model-v001`: v1 features (25, includes 3 leaky) — status: validated
- `model-v002`: v2 features (22, leak-free) — status: active (demo only)

Both achieved F1=1.0 on the synthetic dataset, which is perfectly separable
by design. This is a dataset limitation, NOT proof of real-world validity.
