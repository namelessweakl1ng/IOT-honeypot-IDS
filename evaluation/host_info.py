"""Capture reproducible local host/platform provenance without remote access."""

import argparse
import json
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .preflight import inspect_clock


def version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return (result.stdout or result.stderr).strip().splitlines()[0] if result.returncode == 0 and (result.stdout or result.stderr).strip() else None


def capture(role: str) -> dict:
    clock = inspect_clock()
    revision = version(["git", "rev-parse", "HEAD"])
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "role": role,
        "host_label": role,
        "hostname": socket.gethostname() or None,
        "platform": platform.platform() or None,
        "kernel": platform.release() or None,
        "architecture": platform.machine() or None,
        "python_version": platform.python_version() or None,
        "docker_version": version(["docker", "--version"]),
        "docker_compose_version": version(["docker", "compose", "version"]),
        "utc_system_time": clock["checked_at_utc"],
        "timezone": clock["timezone"] or None,
        "ntp_synchronization": {"status": clock["status"], "synchronized": clock["ntp_synchronized"], "source": clock["source"]},
        "git_software_revision": revision if revision and len(revision) == 40 else None,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Capture local TRAPSIG host provenance")
    parser.add_argument("--role", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    payload = json.dumps(capture(args.role), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
    else:
        sys.stdout.write(payload)


if __name__ == "__main__":
    main()
