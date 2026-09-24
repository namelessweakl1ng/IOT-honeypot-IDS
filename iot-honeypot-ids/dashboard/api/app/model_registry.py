"""Lightweight ML model registry — reads/writes JSON metadata under model_path."""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import settings

log = logging.getLogger("model_registry")


def _models_dir() -> Path:
    """Return the configured models directory.

    Creates it (and parents) if missing AND creatable. If the path points
    to a location we cannot create (e.g. running outside Docker with the
    default /app/... path), returns the path WITHOUT creating — caller
    handles the "doesn't exist" case via .exists() checks.
    """
    p = Path(settings.model_path)
    if not p.exists():
        try:
            p.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError) as exc:
            log.warning("models dir %s could not be created: %s", p, exc)
            return p  # return path anyway; caller checks .exists()
    return p


def list_models() -> List[Dict[str, Any]]:
    """List all models under the models directory.

    Supports two layouts:
      1. flat:     models/<model_id>/metadata.json
      2. grouped:  models/<group>/<model_id>/metadata.json
         (e.g. models/legacy-demo/model-v001/metadata.json)

    A 'group' directory is one that contains model subdirectories but no
    metadata.json of its own. This lets us organize models by provenance
    (legacy-demo, production, experiment-2024-q1, etc.) without the
    dashboard losing visibility into them.
    """
    out: List[Dict[str, Any]] = []
    models_dir = _models_dir()
    if not models_dir.exists():
        log.debug("models dir does not exist: %s", models_dir)
        return out
    # Recursively find all metadata.json files (max depth 3 to avoid scanning
    # huge trees if someone accidentally points MODEL_PATH at /).
    for meta_file in sorted(models_dir.rglob("metadata.json")):
        try:
            rel = meta_file.relative_to(models_dir)
            if len(rel.parts) > 3:  # too deep — skip
                continue
        except ValueError:
            continue
        try:
            out.append(json.loads(meta_file.read_text()))
        except Exception as exc:  # noqa: BLE001
            log.error("could not read metadata for %s: %s", meta_file, exc)
    return out


def get_model(model_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single model by id.

    Searches both flat (models/<model_id>/metadata.json) and grouped
    (models/<group>/<model_id>/metadata.json) layouts.
    """
    models_dir = _models_dir()
    # Try flat layout first
    meta = models_dir / model_id / "metadata.json"
    if meta.exists():
        return json.loads(meta.read_text())
    # Try grouped layout: scan subdirectories
    if models_dir.exists():
        for entry in models_dir.iterdir():
            if not entry.is_dir():
                continue
            candidate = entry / model_id / "metadata.json"
            if candidate.exists():
                return json.loads(candidate.read_text())
    return None


def register_model(
    *,
    model_id: str,
    algorithm: str,
    dataset_version: str,
    feature_version: str,
    features: List[str],
    hyperparameters: Dict[str, Any],
    metrics: Dict[str, float],
    seed: int,
    status: str = "experimental",
    notes: str = "",
) -> Dict[str, Any]:
    """Persist a model registry entry. Never overwrites — caller must version."""
    entry = _models_dir() / model_id
    if entry.exists():
        raise FileExistsError(f"model {model_id} already exists")
    entry.mkdir(parents=True)
    meta = {
        "model_id": model_id,
        "algorithm": algorithm,
        "dataset_version": dataset_version,
        "feature_version": feature_version,
        "features": features,
        "hyperparameters": hyperparameters,
        "metrics": metrics,
        "seed": seed,
        "status": status,
        "notes": notes,
        "created_at": int(time.time()),
        "created_at_iso": _iso_now(),
    }
    (entry / "metadata.json").write_text(json.dumps(meta, indent=2))
    (entry / "README.md").write_text(_model_readme(meta))
    return meta


def update_status(model_id: str, status: str) -> Optional[Dict[str, Any]]:
    """Update a model's status with state-machine validation.

    State transitions (enforced):
      experimental → candidate → validated → active → retired
    - 'active' requires current status='validated'.
    - 'validated' requires validation_metrics to be recorded.
    - Single active model per role (auto-retires previous active).
    """
    meta_path = _find_meta_path(model_id)
    if meta_path is None:
        return None
    meta = json.loads(meta_path.read_text())
    current_status = meta.get("status", "experimental")

    if status == "active":
        if current_status != "validated":
            raise ValueError(
                f"Cannot activate model {model_id} — current status is "
                f"'{current_status}', must be 'validated' first."
            )
        role = meta.get("role", "default")
        _retire_other_active_models(role, exclude_model_id=model_id)
    elif status == "validated":
        val_metrics = meta.get("validation_metrics") or meta.get("metrics", {}).get("validation")
        if not val_metrics:
            raise ValueError(
                f"Cannot validate model {model_id} — no validation_metrics recorded."
            )
    elif status not in ("experimental", "candidate", "retired"):
        raise ValueError(f"Unknown status: {status!r}")

    meta["status"] = status
    meta["updated_at_iso"] = _iso_now()
    meta_path.write_text(json.dumps(meta, indent=2))
    return meta


def _find_meta_path(model_id: str) -> Optional[Path]:
    models_dir = _models_dir()
    if not models_dir.exists():
        return None
    flat = models_dir / model_id / "metadata.json"
    if flat.exists():
        return flat
    for entry in models_dir.iterdir():
        if not entry.is_dir():
            continue
        candidate = entry / model_id / "metadata.json"
        if candidate.exists():
            return candidate
    return None


def _retire_other_active_models(role: str, exclude_model_id: str) -> int:
    retired = 0
    for m in list_models():
        if m.get("status") != "active":
            continue
        if m.get("model_id") == exclude_model_id:
            continue
        m_role = m.get("role", "default")
        if m_role != role:
            continue
        meta_path = _find_meta_path(m["model_id"])
        if meta_path is None:
            continue
        m["status"] = "retired"
        m["updated_at_iso"] = _iso_now()
        m["retired_reason"] = f"superseded by {exclude_model_id}"
        meta_path.write_text(json.dumps(m, indent=2))
        retired += 1
        log.info("retired model %s (role=%s) — superseded by %s",
                  m["model_id"], m_role, exclude_model_id)
    return retired


def get_active_model(role: str = "default") -> Optional[Dict[str, Any]]:
    """Return the active model for the given role, or None if none active."""
    for m in list_models():
        if m.get("status") == "active" and m.get("role", "default") == role:
            return m
    return None


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _model_readme(meta: Dict[str, Any]) -> str:
    features_md = ", ".join(f"`{f}`" for f in meta["features"])
    return f"""# {meta['model_id']}

- Algorithm: `{meta['algorithm']}`
- Dataset version: `{meta['dataset_version']}`
- Feature version: `{meta['feature_version']}`
- Status: `{meta['status']}`
- Created: `{meta['created_at_iso']}`
- Random seed: `{meta['seed']}`

## Hyperparameters

```json
{json.dumps(meta['hyperparameters'], indent=2)}
```

## Metrics

```json
{json.dumps(meta['metrics'], indent=2)}
```

## Features

{features_md}

## Notes

{meta.get('notes', '')}
"""

