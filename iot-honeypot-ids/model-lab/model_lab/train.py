"""Train a model from a dataset.

Usage:
    python -m model_lab.train --algorithm random_forest --seed 42
"""
from __future__ import annotations

import argparse
import json
import sys
import time
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

from features import FEATURE_NAMES  # type: ignore  # noqa: E402
from models import train as train_model  # type: ignore  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train a model")
    parser.add_argument("--algorithm", default="random_forest",
                        choices=["logistic_regression", "random_forest",
                                 "gradient_boosting", "isolation_forest"])
    parser.add_argument("--dataset-version", default="v1")
    parser.add_argument("--dataset-path", default=None,
                        help="Override dataset path (default: datasets/<version>/sessions.csv)")
    parser.add_argument("--feature-version", default="v1")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model-id", default=None,
                        help="Override model id (default: model-v<timestamp>)")
    parser.add_argument("--notes", default="")
    parser.add_argument("--test-ratio", type=float, default=0.2)
    args = parser.parse_args(argv)

    # Load dataset
    ds_path = Path(args.dataset_path) if args.dataset_path else datasets_dir() / args.dataset_version / "sessions.csv"
    if not ds_path.exists():
        print(f"ERROR: dataset not found: {ds_path}", file=sys.stderr)
        print("  Run `python -m model_lab.datasets.bootstrap --out <path>` first.", file=sys.stderr)
        return 2

    df = pd.read_csv(ds_path)
    if "label" not in df.columns:
        print("ERROR: dataset missing 'label' column", file=sys.stderr)
        return 3

    # Build feature dicts + labels
    X = df[FEATURE_NAMES].to_dict(orient="records")
    y = df["label"].astype(str).tolist()

    # Model id
    model_id = args.model_id or f"model-v{int(time.time())}"
    print(f"training {model_id} (algorithm={args.algorithm}, seed={args.seed}, n={len(X)})")

    # Train (in-sample metrics; caller should run `evaluate` for a held-out set).
    meta = train_model(
        X=X,
        y=y,
        algorithm=args.algorithm,
        seed=args.seed,
        models_dir=models_dir(),
        model_id=model_id,
        dataset_version=args.dataset_version,
        feature_version=args.feature_version,
        notes=args.notes,
    )

    if isinstance(meta, dict) and meta.get("status") == "INSUFFICIENT DATA":
        print(meta)
        return 4

    print(f"OK: model written to {models_dir() / model_id}")
    print(json.dumps(meta["metrics"], indent=2))

    # Record experiment metadata
    experiments_dir().mkdir(parents=True, exist_ok=True)
    exp = {
        "experiment_id": f"exp-{int(time.time())}",
        "model_id": model_id,
        "algorithm": args.algorithm,
        "dataset_version": args.dataset_version,
        "feature_version": args.feature_version,
        "seed": args.seed,
        "metrics": meta.get("metrics", {}),
        "notes": args.notes,
    }
    exp_path = experiments_dir() / f"{exp['experiment_id']}.json"
    exp_path.write_text(json.dumps(exp, indent=2, default=str))
    print(f"experiment recorded at {exp_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
