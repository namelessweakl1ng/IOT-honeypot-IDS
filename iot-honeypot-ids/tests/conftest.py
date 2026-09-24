"""Pytest fixtures shared across all tests."""
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def add_dashboard_ml_to_path() -> None:
    """Make dashboard/ml + shared/schemas importable from any test."""
    root = Path(__file__).resolve().parent.parent
    for sub in ("dashboard/ml", "shared"):
        p = str(root / sub)
        if p not in sys.path:
            sys.path.insert(0, p)
