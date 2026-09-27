#!/usr/bin/env python3
"""Run a reproducible scenario-held-out IoT-23 flow classifier experiment."""
from __future__ import annotations

import argparse
import hashlib
import json
import joblib
import os
import platform
import re
import random
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "model-lab"))
from model_lab.datasets.iot23_features import FEATURE_VERSION, NUMERIC_FEATURES, audit_feature_names, feature_vector, scenario_split, temporal_split  # noqa: E402
from model_lab.datasets.validate_iot23 import validate as validate_iot23  # noqa: E402


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "-C", str(ROOT.parent), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "UNKNOWN"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", required=True, type=Path, help="prepared normalized/flows.jsonl")
    p.add_argument("--experiment-id", required=True)
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--algorithm", required=True, choices=("logistic_regression", "random_forest", "gradient_boosting", "isolation_forest"))
    p.add_argument("--feature-version", required=True, choices=(FEATURE_VERSION,))
    p.add_argument("--split-protocol", required=True, choices=("scenario", "temporal"), help="scenario = disjoint scenario-level holdout; temporal = chronological flow holdout, with scenario overlap expected")
    p.add_argument("--max-flows-per-scenario", type=int, default=10000)
    p.add_argument("--output", type=Path, default=ROOT / "research" / "experiments" / "iot23")
    args = p.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", args.experiment_id):
        raise SystemExit("ERROR: experiment ID must use 1-100 safe letters, numbers, dots, underscores, or dashes")
    dataset = args.dataset.resolve()
    if not dataset.is_file():
        raise SystemExit(f"ERROR: prepared IoT-23 file not found: {dataset}. Run prepare-iot23.sh; there is no demo or synthetic fallback.")
    validation = validate_iot23(dataset, expected_scenarios=23)
    if "validation_error" in validation:
        raise SystemExit(f"ERROR: IoT-23 validation failed: {validation['validation_error']}")
    if args.max_flows_per_scenario < 1:
        raise SystemExit("ERROR: --max-flows-per-scenario must be positive")
    audit_feature_names(list(NUMERIC_FEATURES))

    # Uniform deterministic per-scenario reservoir sample bounds memory and
    # avoids selecting only the beginning of a potentially enormous capture.
    rng = random.Random(args.seed)
    rows: dict[str, list[dict]] = defaultdict(list)
    seen: dict[str, int] = defaultdict(int)
    excluded_unmapped = 0
    with dataset.open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("dataset_id") != "iot23" or row.get("dataset_version") != "1.0.0":
                raise SystemExit(f"ERROR: row {line_number} does not identify IoT-23 version 1.0.0")
            if row.get("label_source") != "EXTERNAL_DATASET" or row.get("data_category") != "PUBLIC_DATASET":
                raise SystemExit(f"ERROR: row {line_number} is not labeled PUBLIC_DATASET/EXTERNAL_DATASET; research runner rejects development or synthetic provenance")
            scenario = str(row.get("source_scenario", ""))
            label = str(row.get("project_label", "UNMAPPED"))
            if label in {"UNMAPPED", "unknown", "UNKNOWN", ""}:
                excluded_unmapped += 1
                continue
            if not scenario:
                raise SystemExit(f"ERROR: row {line_number} has no source_scenario")
            try:
                features = feature_vector(row)
            except ValueError as exc:
                raise SystemExit(f"ERROR: invalid feature in row {line_number}: {exc}")
            item = {"scenario": scenario, "record_id": row.get("record_id", f"row-{line_number}"), "timestamp": row.get("timestamp"), "label": label, "original_label": row.get("original_label"), "binary_label": str(row.get("binary_label", "unknown")).lower(), "features": features}
            seen[scenario] += 1
            bucket = rows[scenario]
            if len(bucket) < args.max_flows_per_scenario:
                bucket.append(item)
            else:
                index = rng.randrange(seen[scenario])
                if index < args.max_flows_per_scenario:
                    bucket[index] = item
    scenarios = sorted(rows)
    all_rows = [row for scenario in scenarios for row in rows[scenario]]
    if args.split_protocol == "scenario":
        scenario_splits = scenario_split(scenarios, seed=args.seed)
        assert not (set(scenario_splits["train"]) & set(scenario_splits["validation"]) or set(scenario_splits["train"]) & set(scenario_splits["test"]) or set(scenario_splits["validation"]) & set(scenario_splits["test"]))
        by_split = {key: [row for row in all_rows if row["scenario"] in value] for key, value in scenario_splits.items()}
        split_definition = {"protocol": "SCENARIO_HOLDOUT", "scenarios": scenario_splits, "overlap": {"train_validation": [], "train_test": [], "validation_test": []}, "unmapped_rows_excluded": excluded_unmapped}
    else:
        temporal = temporal_split(all_rows)
        by_split = temporal["indices"]
        split_definition = {**temporal["metadata"], "scenario_sets": {key: sorted({r["scenario"] for r in value}) for key, value in by_split.items()}, "unmapped_rows_excluded": excluded_unmapped}
    train, validation, test = (by_split[k] for k in ("train", "validation", "test"))
    if not train or not validation or not test:
        raise SystemExit("ERROR: scenario split has an empty partition; provide at least 3 usable scenarios")
    y_train = [r["label"] for r in train]
    if args.algorithm != "isolation_forest" and len(set(y_train)) < 2:
        raise SystemExit("ERROR: training scenarios contain fewer than two project classes; protocol is not evaluable")
    if args.algorithm == "isolation_forest" and len({r["binary_label"] for r in train}) < 2:
        raise SystemExit("ERROR: Isolation Forest evaluation requires benign and malicious labels in training data")

    from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    if args.algorithm == "logistic_regression":
        model = make_pipeline(SimpleImputer(strategy="median"), StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced", random_state=args.seed))
        params = {"max_iter": 1000, "class_weight": "balanced", "random_state": args.seed}
    elif args.algorithm == "random_forest":
        model = make_pipeline(SimpleImputer(strategy="median"), RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=args.seed, n_jobs=-1))
        params = {"n_estimators": 300, "class_weight": "balanced", "random_state": args.seed, "n_jobs": -1}
    elif args.algorithm == "gradient_boosting":
        model = make_pipeline(SimpleImputer(strategy="median"), GradientBoostingClassifier(random_state=args.seed))
        params = {"random_state": args.seed}
    else:
        model = make_pipeline(SimpleImputer(strategy="median"), IsolationForest(n_estimators=300, contamination=0.05, random_state=args.seed, n_jobs=-1))
        params = {"n_estimators": 300, "contamination": 0.05, "random_state": args.seed, "fit_population": "benign training flows only"}

    X = lambda subset: [[float("nan") if r["features"][name] is None else r["features"][name] for name in NUMERIC_FEATURES] for r in subset]
    if args.algorithm == "isolation_forest":
        benign_train = [r for r in train if r["binary_label"] == "benign"]
        if len(benign_train) < 2:
            raise SystemExit("ERROR: Isolation Forest requires at least two benign training flows")
        model.fit(X(benign_train))
        classes = ["benign", "malicious"]
    else:
        model.fit(X(train), y_train)
        classes = sorted(set([r["label"] for r in train + validation + test]))
    output = args.output / args.experiment_id
    output.mkdir(parents=True, exist_ok=False)
    joblib.dump(model, output / "model.joblib")
    prediction_rows = []
    metrics_by_partition = {}
    matrix_by_partition = {}
    for name, subset in (("validation", validation), ("test", test)):
        truth = [r["binary_label"] for r in subset] if args.algorithm == "isolation_forest" else [r["label"] for r in subset]
        raw_predictions = model.predict(X(subset)).tolist()
        predicted = ["benign" if prediction == 1 else "malicious" for prediction in raw_predictions] if args.algorithm == "isolation_forest" else [str(x) for x in raw_predictions]
        report = classification_report(truth, predicted, labels=classes, output_dict=True, zero_division=0)
        binary_truth = [r["binary_label"] for r in subset]
        binary_pred = predicted if args.algorithm == "isolation_forest" else ["benign" if str(x).lower() in {"benign", "normal"} else "malicious" for x in predicted]
        tp_b = sum(t == "benign" and q == "benign" for t, q in zip(binary_truth, binary_pred))
        fp = sum(t == "benign" and q == "malicious" for t, q in zip(binary_truth, binary_pred))
        fn = sum(t == "malicious" and q == "benign" for t, q in zip(binary_truth, binary_pred))
        tn = sum(t == "malicious" and q == "malicious" for t, q in zip(binary_truth, binary_pred))
        from sklearn.metrics import balanced_accuracy_score
        metrics_by_partition[name] = {"accuracy": accuracy_score(truth, predicted), "balanced_accuracy": balanced_accuracy_score(truth, predicted), "precision_macro": precision_score(truth, predicted, average="macro", labels=classes, zero_division=0), "recall_macro": recall_score(truth, predicted, average="macro", labels=classes, zero_division=0), "f1_macro": f1_score(truth, predicted, average="macro", labels=classes, zero_division=0), "per_class": report, "binary_fpr": fp / (fp + tp_b) if (fp + tp_b) else None, "binary_fnr": fn / (fn + tn) if (fn + tn) else None, "n": len(subset), "roc_auc_ovr_macro": None, "pr_auc_ovr_macro": None}
        try:
            from sklearn.metrics import average_precision_score, roc_auc_score
            if args.algorithm == "isolation_forest":
                binary_truth_values = [1 if label == "malicious" else 0 for label in binary_truth]
                anomaly_scores = -model.decision_function(X(subset))
                if len(set(binary_truth_values)) == 2:
                    metrics_by_partition[name]["roc_auc_ovr_macro"] = roc_auc_score(binary_truth_values, anomaly_scores)
                    metrics_by_partition[name]["pr_auc_ovr_macro"] = average_precision_score(binary_truth_values, anomaly_scores)
            elif hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(X(subset))
                model_classes = list(model.classes_) if hasattr(model, "classes_") else list(model[-1].classes_)
                from sklearn.preprocessing import label_binarize
                one_hot = label_binarize(truth, classes=model_classes)
                if len(model_classes) == 2 and one_hot.shape[1] == 1:
                    one_hot = __import__("numpy").column_stack((1 - one_hot[:, 0], one_hot[:, 0]))
                metrics_by_partition[name]["roc_auc_ovr_macro"] = roc_auc_score(one_hot, probabilities, average="macro", multi_class="ovr")
                metrics_by_partition[name]["pr_auc_ovr_macro"] = average_precision_score(one_hot, probabilities, average="macro")
        except (ValueError, AttributeError):
            pass
        matrix_by_partition[name] = {"labels": classes, "matrix": confusion_matrix(truth, predicted, labels=classes).tolist()}
        prediction_rows += [{"partition": name, "record_id": r["record_id"], "source_scenario": r["scenario"], "timestamp": r["timestamp"], "original_label": r["original_label"], "original_project_label": r["label"], "observed_label": truth_i, "prediction": str(pred), "prediction_source": "MODEL_PREDICTION", "label_source": "EXTERNAL_DATASET", "data_category": "PUBLIC_DATASET"} for r, pred, truth_i in zip(subset, predicted, truth)]

    digest = hashlib.sha256()
    with dataset.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    input_hash = digest.hexdigest()
    model_digest = hashlib.sha256((output / "model.joblib").read_bytes()).hexdigest()
    commit = git_commit()
    created_at = datetime.now(timezone.utc).isoformat()
    train_test_overlap = sorted({r["record_id"] for r in train} & {r["record_id"] for r in test})
    validity = "VALID" if not train_test_overlap and len(train) and len(test) else "INVALID"
    context = {"experiment_id": args.experiment_id, "git_commit": commit, "dataset_name": "IoT-23", "dataset_version": "1.0.0", "data_category": "PUBLIC_DATASET", "feature_version": args.feature_version, "seed": args.seed, "algorithm": args.algorithm, "hyperparameters": params, "split_protocol": split_definition["protocol"], "train_size": len(train), "validation_size": len(validation), "test_size": len(test), "label_source": "EXTERNAL_DATASET", "validity": validity, "created_at_utc": created_at}
    manifest = {**context, "input_file_sha256": input_hash, "split_definition": split_definition, "train_test_record_overlap": train_test_overlap, "sampling": {"method": "seeded per-scenario reservoir", "max_flows_per_scenario": args.max_flows_per_scenario, "seen_flows_by_scenario": dict(seen), "retained_flows_by_scenario": {k: len(v) for k, v in rows.items()}, "unmapped_rows_excluded": excluded_unmapped}, "model_sha256": model_digest}
    artifacts = {"manifest.json": manifest, "dataset.json": {"path": str(dataset), "sha256": input_hash, "scenario_count": len(scenarios), "flow_count": len(all_rows), "classes": classes, "label_source": "EXTERNAL_DATASET", "data_category": "PUBLIC_DATASET"}, "split.json": split_definition, "model.json": {"dataset_name": "IoT-23", "dataset_version": "1.0.0", "data_category": "PUBLIC_DATASET", "algorithm": args.algorithm, "hyperparameters": params, "seed": args.seed, "experiment_id": args.experiment_id, "git_commit": commit, "model_sha256": model_digest, "feature_names": list(NUMERIC_FEATURES), "feature_version": args.feature_version, "split_protocol": split_definition["protocol"], "train_size": len(train), "test_size": len(test), "label_source": "EXTERNAL_DATASET", "validity": validity, "created_at_utc": created_at}, "metrics.json": {"selection_note": "No hyperparameter tuning was performed; validation metrics are descriptive. Test partition was evaluated once after fitting.", "results": metrics_by_partition}, "predictions.json": prediction_rows, "confusion_matrix.json": matrix_by_partition, "environment.json": {"python": sys.version, "platform": platform.platform(), "numpy": __import__("numpy").__version__, "pandas": __import__("pandas").__version__, "scikit_learn": __import__("sklearn").__version__, "seed": args.seed}}
    for filename, data in artifacts.items():
        if isinstance(data, dict):
            data = {"experiment_context": context, **data}
        else:
            data = {"experiment_context": context, "records": data}
        (output / filename).write_text(json.dumps(data, indent=2, default=float) + "\n", encoding="utf-8")
    split_summary = "whole scenarios are held apart" if args.split_protocol == "scenario" else "flows are chronologically held apart; scenario overlap is expected"
    (output / "README.md").write_text(f"# Experiment {args.experiment_id}\n\n- Git commit: `{commit}`\n- Dataset: IoT-23 `1.0.0` (PUBLIC_DATASET; see input hash in `manifest.json`)\n- Algorithm: `{args.algorithm}`\n- Feature version: `{args.feature_version}`\n- Seed: `{args.seed}`\n- Split: `{split_definition['protocol']}`; {split_summary}\n- Rows: train {len(train)}, validation {len(validation)}, test {len(test)}\n- Label source: EXTERNAL_DATASET (analyst-derived source labels)\n- Validity: {validity}\n- Hyperparameters: `{json.dumps(params, sort_keys=True)}`\n\nA seeded per-scenario reservoir cap of {args.max_flows_per_scenario} flows is applied. Preprocessing is fit only on training data. No test data was used for fitting or tuning.\n", encoding="utf-8")
    print(f"Experiment artifacts: {output}")
    print(json.dumps(metrics_by_partition["test"], indent=2, default=float))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
