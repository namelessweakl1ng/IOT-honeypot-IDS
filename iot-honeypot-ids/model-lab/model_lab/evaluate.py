"""Evaluate a model on a held-out session-level split.

Usage:
    python -m model_lab.evaluate --model-id model-v001
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

# Support both `python -m model_lab.evaluate` (relative) and
# `python -m model_lab.evaluate` from a different CWD (absolute fallback).
try:
    from .common import datasets_dir, experiments_dir, models_dir, setup_paths
    setup_paths()
except ImportError:
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    from common import datasets_dir, experiments_dir, models_dir, setup_paths  # type: ignore
    setup_paths()

# Import the dashboard/ml/evaluate.py module — but rename it to avoid
# a name clash with this file (model_lab/evaluate.py). We load it explicitly
# from its file path.
import importlib.util as _ilu
_eval_path = Path(__file__).resolve().parents[2] / "dashboard" / "ml" / "evaluate.py"
_spec = _ilu.spec_from_file_location("dashboard_ml_evaluate", _eval_path)
_mod_evaluate = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod_evaluate)
evaluate_classification = _mod_evaluate.evaluate_classification
session_level_split = _mod_evaluate.session_level_split

from features import FEATURE_NAMES  # type: ignore  # noqa: E402
from models import load, predict  # type: ignore  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a model")
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--dataset-version", default="v1")
    parser.add_argument("--dataset-path", default=None)
    parser.add_argument("--test-ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    ds_path = Path(args.dataset_path) if args.dataset_path else datasets_dir() / args.dataset_version / "sessions.csv"
    if not ds_path.exists():
        print(f"ERROR: dataset not found: {ds_path}", file=sys.stderr)
        return 2

    df = pd.read_csv(ds_path)
    if "label" not in df.columns or "session_id" not in df.columns:
        print("ERROR: dataset must have 'session_id' and 'label' columns", file=sys.stderr)
        return 3

    # Session-level split (no leakage)
    train_idx, test_idx = session_level_split(
        session_ids=df["session_id"].tolist(),
        labels=df["label"].astype(str).tolist(),
        test_ratio=args.test_ratio,
        seed=args.seed,
    )
    if not test_idx:
        print("WARN: empty test set — try a larger dataset or a different seed", file=sys.stderr)

    test_df = df.iloc[test_idx]
    # Load model first so we know which feature version it was trained with
    estimator, scaler, meta = load(models_dir(), args.model_id)
    fv = meta.get("feature_version", "v1")
    if fv == "v2":
        from features import FEATURE_NAMES_V2 as FEAT  # type: ignore
    else:
        from features import FEATURE_NAMES as FEAT  # type: ignore
    X = test_df[FEAT].to_dict(orient="records")
    y_true = test_df["label"].astype(str).tolist()

    # Predict
    preds = predict(models_dir(), args.model_id, X)
    y_pred = [p["prediction"] for p in preds]

    metrics = evaluate_classification(y_true, y_pred)
    print(json.dumps(metrics, indent=2, default=str))

    # Also persist the held-out metrics INTO the model metadata so the
    # dashboard can show them alongside the in-sample metrics.
    meta_path = models_dir() / args.model_id / "metadata.json"
    meta["metrics"]["accuracy"] = metrics["accuracy"]
    meta["metrics"]["precision_macro"] = metrics["precision_macro"]
    meta["metrics"]["recall_macro"] = metrics["recall_macro"]
    meta["metrics"]["f1_macro"] = metrics["f1_macro"]
    meta["metrics"]["n_test"] = len(test_idx)
    meta["metrics"]["n_train"] = len(train_idx)
    meta["metrics"]["confusion_matrix"] = metrics["confusion_matrix"]
    meta["metrics"]["confusion_matrix_labels"] = metrics["confusion_matrix_labels"]
    meta["metrics"]["per_class"] = metrics["per_class"]
    meta["metrics"]["false_positive_rate"] = metrics["false_positive_rate"]
    meta["metrics"]["false_negative_rate"] = metrics["false_negative_rate"]
    meta["metrics"]["evaluated_at_iso"] = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if meta["status"] == "experimental":
        meta["status"] = "validated"  # held-out eval promotes the model
    meta_path.write_text(json.dumps(meta, indent=2, default=str))
    print(f"model metadata updated: {meta_path}")

    # Persist evaluation as an experiment
    experiments_dir().mkdir(parents=True, exist_ok=True)
    import time
    exp_id = f"exp-eval-{args.model_id}-{int(time.time())}"
    exp = {
        "experiment_id": exp_id,
        "model_id": args.model_id,
        "algorithm": meta["algorithm"],
        "dataset_version": args.dataset_version,
        "feature_version": fv,
        "seed": args.seed,
        "metrics": metrics,
        "split": {"train_size": len(train_idx), "test_size": len(test_idx), "test_ratio": args.test_ratio},
        "notes": "session-level held-out evaluation",
    }
    (experiments_dir() / f"{exp_id}.json").write_text(json.dumps(exp, indent=2, default=str))
    print(f"experiment recorded at {experiments_dir() / (exp_id + '.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
