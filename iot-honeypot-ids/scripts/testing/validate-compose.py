#!/usr/bin/env python3
"""Validate docker-compose.yml files without Docker installed.

Parses the YAML and checks:
- All referenced files exist (bind-mount sources)
- All volumes are declared in the `volumes:` top-level section
- All services have correct dependencies (no missing services)
- No duplicate/shadowed volume mounts on the same path inside one service
- All env vars referenced in ${VAR:-default} are documented in .env.example
- Health checks are valid
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO = Path(__file__).resolve().parents[2]
errs: List[str] = []
warns: List[str] = []


def load_compose(path: Path) -> Tuple[Dict[str, Any], str]:
    if not path.exists():
        errs.append(f"compose file not found: {path}")
        return {}, ""
    text = path.read_text()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        errs.append(f"YAML parse error in {path}: {e}")
        return {}, text
    if not isinstance(data, dict):
        errs.append(f"compose root is not a dict: {path}")
        return {}, text
    return data, text


def check_volumes_declared(data: Dict[str, Any], compose_path: Path) -> None:
    """Every named volume mounted by a service must be declared in volumes:."""
    declared: Set[str] = set((data.get("volumes") or {}).keys())
    services = data.get("services") or {}
    for svc_name, svc in services.items():
        vols = svc.get("volumes") or []
        seen_paths: Dict[str, str] = {}
        for v in vols:
            if isinstance(v, str):
                parts = v.split(":")
                if len(parts) < 2:
                    continue
                src = parts[0]
                dst = parts[1]
                # If src is a relative path (./foo or ../foo), check it exists
                if src.startswith(".") or src.startswith("/"):
                    resolved = (compose_path.parent / src).resolve()
                    if not resolved.exists():
                        errs.append(f"service '{svc_name}': bind-mount source '{src}' does not exist (resolved: {resolved})")
                else:
                    # Named volume — must be declared
                    if src not in declared:
                        errs.append(f"service '{svc_name}': volume '{src}' is not declared in top-level volumes:")
                # Check for shadowed mounts on the same container path
                if dst in seen_paths:
                    errs.append(f"service '{svc_name}': container path '{dst}' mounted twice (shadowed) — "
                                f"first as '{seen_paths[dst]}', then as '{v}'")
                seen_paths[dst] = v


def check_depends_on(data: Dict[str, Any]) -> None:
    services = set((data.get("services") or {}).keys())
    for svc_name, svc in (data.get("services") or {}).items():
        deps = svc.get("depends_on") or {}
        if isinstance(deps, dict):
            for dep in deps.keys():
                if dep not in services:
                    errs.append(f"service '{svc_name}': depends_on '{dep}' is not a defined service")
        elif isinstance(deps, list):
            for dep in deps:
                if dep not in services:
                    errs.append(f"service '{svc_name}': depends_on '{dep}' is not a defined service")


def check_healthchecks(data: Dict[str, Any]) -> None:
    for svc_name, svc in (data.get("services") or {}).items():
        hc = svc.get("healthcheck")
        if hc is None:
            continue
        if not isinstance(hc, dict):
            errs.append(f"service '{svc_name}': healthcheck must be a dict")
            continue
        test = hc.get("test")
        if test is None:
            errs.append(f"service '{svc_name}': healthcheck missing 'test'")
            continue
        if isinstance(test, list) and len(test) == 0:
            errs.append(f"service '{svc_name}': healthcheck test list is empty")
        if isinstance(test, str) and not test.strip():
            errs.append(f"service '{svc_name}': healthcheck test string is empty")


def check_env_refs(data: Dict[str, Any], compose_path: Path) -> None:
    """Every ${VAR:-default} or ${VAR} referenced should be in .env.example."""
    # Recursively walk services and find ${VAR} patterns in env: lists + values.
    text = compose_path.read_text()
    refs = set(re.findall(r"\$\{([A-Z_][A-Z0-9_]*)(?::-[^}]*)?\}", text))
    env_example = compose_path.parent / ".env.example"
    if not env_example.exists():
        warns.append(f"no .env.example found at {env_example}")
        return
    declared_env = set()
    for line in env_example.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            declared_env.add(line.split("=", 1)[0])
    for ref in refs:
        if ref not in declared_env:
            warns.append(f"compose references ${{{ref}}} but it is not declared in {env_example.name}")


def main() -> int:
    for compose_file in [
        REPO / "pi" / "docker-compose.yml",
        REPO / "dashboard" / "docker-compose.yml",
    ]:
        print(f"\n=== Validating {compose_file.relative_to(REPO)} ===")
        data, _text = load_compose(compose_file)
        if not data:
            continue
        check_volumes_declared(data, compose_file)
        check_depends_on(data)
        check_healthchecks(data)
        check_env_refs(data, compose_file)
        # Profile check: ensure honeypot profiles don't prevent required telemetry
        services = data.get("services") or {}
        for name, svc in services.items():
            profiles = svc.get("profiles")
            if profiles and "default" not in profiles:
                # If a telemetry-critical service is in a non-default profile,
                # warn — operators may forget to enable it.
                if name in {"filebeat", "elasticsearch", "logstash", "api"}:
                    warns.append(f"service '{name}' is in profile(s) {profiles} but is telemetry-critical — "
                                 f"operators must explicitly enable the profile to start telemetry")

    print("\n=== Summary ===")
    if warns:
        print(f"warnings ({len(warns)}):")
        for w in warns:
            print(f"  WARN: {w}")
    if errs:
        print(f"errors ({len(errs)}):")
        for e in errs:
            print(f"  ERROR: {e}")
        return 1
    print("OK — compose files validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
