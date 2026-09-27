#!/usr/bin/env python3
"""Compatibility entry point for the canonical IoT-23 validator."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
env = {**os.environ, "PYTHONPATH": str(ROOT / "model-lab") + os.pathsep + os.environ.get("PYTHONPATH", "")}
raise SystemExit(subprocess.call([sys.executable, "-m", "model_lab.datasets.validate_iot23", *sys.argv[1:]], cwd=ROOT, env=env))
