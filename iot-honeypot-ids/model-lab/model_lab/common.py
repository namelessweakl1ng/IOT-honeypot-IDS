"""Common helpers — sys.path setup + shared CLI args."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def setup_paths() -> None:
    """Add `dashboard/ml` to sys.path so model_lab can import features / models."""
    here = Path(__file__).resolve().parent
    repo_root = here.parent.parent  # iot-honeypot-ids/
    ml_dir = repo_root / "dashboard" / "ml"
    shared_dir = repo_root / "shared"
    for p in (str(ml_dir), str(shared_dir), str(here)):
        if p not in sys.path:
            sys.path.insert(0, p)


def models_dir() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "models"


def datasets_dir() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "datasets"


def experiments_dir() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "experiments"
