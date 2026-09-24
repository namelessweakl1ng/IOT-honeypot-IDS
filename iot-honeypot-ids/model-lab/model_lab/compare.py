"""Compare two or more models on the same held-out dataset.

Usage:
    python -m model_lab.compare --model-ids model-v001 model-v002
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

try:
    from .common import datasets_dir, experiments_dir, models_dir, setup_paths
    setup_paths()
except ImportError:
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    from common import datasets_dir, experiments_dir, models_dir, setup_paths  # type: ignore
    setup_paths()

# Import the dashboard/ml/evaluate.py module via file path to avoid name clash.
import importlib.util as _ilu
_eval_path = Path(__file__).resolve().parents[2] / "dashboard" / "ml" / "evaluate.py"
_spec = _ilu.spec_from_file_location("dashboard_ml_evaluate", _eval_path)
_mod_evaluate = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod_evaluate)
evaluate_classification = _mod_evaluate.evaluate_classification
session_level_split = _mod_evaluate.session_level_split

from features import FEATURE_NAMES  # type: ignore  # noqa: E402
from models import predict  # type: ignore  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare multiple models")
    parser.add_argument("--model-ids", nargs="+", required=True)
    parser.add_argument("--dataset-version", default="v1")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-ratio", type=float, default=0.2)
    args = parser.parse_args(argv)

    ds_path = datasets_dir() / args.dataset_version / "sessions.csv"
    if not ds_path.exists():
        print(f"ERROR: dataset not found: {ds_path}", file=sys.stderr)
        return 2
    df = pd.read_csv(ds_path)

    train_idx, test_idx = session_level_split(
        session_ids=df["session_id"].tolist(),
        labels=df["label"].astype(str).tolist(),
        test_ratio=args.test_ratio,
        seed=args.seed,
    )
    test_df = df.iloc[test_idx]
    X = test_df[FEATURE_NAMES].to_dict(orient="records")
    y_true = test_df["label"].astype(str).tolist()

    comparison = {}
    for mid in args.model_ids:
        try:
            preds = predict(models_dir(), mid, X)
            y_pred = [p["prediction"] for p in preds]
            metrics = evaluate_classification(y_true, y_pred)
            comparison[mid] = metrics
        except Exception as exc:  # noqa: BLE001
            comparison[mid] = {"error": str(exc)}

    print(json.dumps(comparison, indent=2, default=str))

    # Persist as a comparison experiment
    experiments_dir().mkdir(parents=True, exist_ok=True)
    import time
    exp = {
        "experiment_id": f"exp-compare-{int(time.time())}",
        "type": "comparison",
        "model_ids": args.model_ids,
        "dataset_version": args.dataset_version,
        "seed": args.seed,
        "results": comparison,
    }
    out = experiments_dir() / f"{exp['experiment_id']}.json"
    out.write_text(json.dumps(exp, indent=2, default=str))
    print(f"comparison recorded at {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
