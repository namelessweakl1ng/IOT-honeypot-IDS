"""Local clock synchronization preflight; run independently on both hosts."""

import json
import subprocess
from datetime import datetime, timezone


def command(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def inspect_clock() -> dict:
    result = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "timezone": str(datetime.now().astimezone().tzinfo),
        "ntp_synchronized": None,
        "status": "UNKNOWN",
        "source": None,
    }
    timedatectl = command(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    if timedatectl and timedatectl.returncode == 0:
        value = timedatectl.stdout.strip().lower()
        result.update(ntp_synchronized=value == "yes", status="PASS" if value == "yes" else "WARNING", source="timedatectl")
        return result
    chronyc = command(["chronyc", "tracking"])
    if chronyc and chronyc.returncode == 0:
        synchronized = "Leap status" in chronyc.stdout and "Not synchronised" not in chronyc.stdout
        result.update(ntp_synchronized=synchronized, status="PASS" if synchronized else "WARNING", source="chronyc")
    return result


def main():
    print(json.dumps(inspect_clock(), indent=2))


if __name__ == "__main__":
    main()
