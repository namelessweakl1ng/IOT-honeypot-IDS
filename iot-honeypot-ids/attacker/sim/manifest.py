"""Experiment manifest writer.

Writes JSON manifests with run_id, scenario, stages, statistics, etc.
NEVER writes secrets (passwords, private keys, API keys). Only records
credential_profile identifiers (e.g. "credential_profile_3") not
plaintext credentials.
"""
from __future__ import annotations

import json
import os
import platform
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .config import ExperimentConfig
from .scenarios.base import ScenarioResult


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def generate_run_id() -> str:
    """Generate a unique run ID: RUN-YYYYMMDD-XXXX."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = secrets.token_hex(3)  # 6 hex chars
    return f"RUN-{date_str}-{suffix}"


def build_manifest(
    run_id: str,
    scenario_name: str,
    config: ExperimentConfig,
    result: ScenarioResult,
    seed: int,
    profile: str,
) -> Dict[str, Any]:
    """Build the manifest dict. NEVER includes secrets."""
    return {
        "run_id": run_id,
        "scenario": scenario_name,
        "started_at": result.started_at or _now_iso(),
        "ended_at": result.ended_at or _now_iso(),
        "target": {
            "ip": config.target_ip,
            "services": {
                "ssh": config.ssh_port,
                "camera": config.camera_port,
                "iot": config.iot_port,
            },
        },
        "attacker": {
            "hostname": platform.node(),
            "platform": platform.platform(),
        },
        "profile": profile,
        "seed": seed,
        "stages": [
            {
                "step": s.step,
                "status": s.status,
                "detail": s.detail,
                "timestamp": s.timestamp,
            }
            for s in result.steps
        ],
        "statistics": result.statistics,
        "status": result.status,
        "error": result.error or None,
        # NO secrets, NO passwords, NO private keys, NO API keys.
        # Credential profiles are identified by index only.
        "credential_profiles": "credential_profile_N (no plaintext recorded)",
    }


def write_manifest(manifest: Dict[str, Any], manifests_dir: str = "manifests") -> Path:
    """Write the manifest to a JSON file. Returns the file path."""
    p = Path(manifests_dir)
    p.mkdir(parents=True, exist_ok=True)
    run_id = manifest.get("run_id", "unknown")
    filename = f"{run_id}.json"
    filepath = p / filename
    with open(filepath, "w") as f:
        json.dump(manifest, f, indent=2)
    return filepath


def audit_manifest_no_secrets(manifest: Dict[str, Any]) -> bool:
    """Audit a manifest for accidentally-included secret material.

    Field-aware audit (final hardening):
      Instead of naively rejecting every occurrence of words like "password"
      or "secret" (which could appear in legitimate field names or documentation
      metadata), this audit:
        1. Inspects specific KNOWN secret-bearing field names for non-empty values
        2. Scans ALL string values for credential-like patterns (password=, key=, etc.)
        3. Allows safe labels like "credential_profile_N" (these are indices, not secrets)

    Returns True if clean, raises AssertionError if a secret is found.
    """
    # Fields that must NEVER contain a value (must be null or absent)
    _FORBIDDEN_FIELDS = [
        "password", "passwd", "pass", "private_key", "api_key",
        "secret", "token", "ssh_key", "key_material", "credential",
    ]

    # Patterns that indicate actual secret material in values
    import re
    _SECRET_PATTERNS = [
        re.compile(r"(?i)password\s*[=:]\s*\S+", re.IGNORECASE),
        re.compile(r"(?i)pass\s*[=:]\s*\S+", re.IGNORECASE),
        re.compile(r"-----BEGIN.*PRIVATE KEY-----", re.IGNORECASE),
        re.compile(r"(?i)api[_-]?key\s*[=:]\s*\S+", re.IGNORECASE),
        re.compile(r"(?i)secret\s*[=:]\s*\S+", re.IGNORECASE),
        re.compile(r"(?i)token\s*[=:]\s*\S+", re.IGNORECASE),
    ]

    def _check_value(field_name: str, value: Any) -> None:
        """Recursively check a value for secret material."""
        if isinstance(value, dict):
            for k, v in value.items():
                _check_value(k, v)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                _check_value(f"{field_name}[{i}]", item)
        elif isinstance(value, str):
            # Check if this field name is a forbidden secret field with a non-empty value
            if field_name.lower() in _FORBIDDEN_FIELDS and value:
                # Allow "credential_profile_N" (label, not secret)
                if field_name.lower() == "credential" and value.startswith("credential_profile_"):
                    return
                # Allow null/None/empty
                if value in ("None", "null", ""):
                    return
                raise AssertionError(
                    f"manifest contains secret field '{field_name}' with value '{value[:50]}...' — "
                    f"manifests must NOT include passwords, private keys, or API keys"
                )
            # Check value for secret-like patterns
            for pattern in _SECRET_PATTERNS:
                if pattern.search(value):
                    raise AssertionError(
                        f"manifest value in field '{field_name}' matches secret pattern: "
                        f"'{value[:50]}...' — manifests must NOT include credential material"
                    )

    _check_value("root", manifest)
    return True
