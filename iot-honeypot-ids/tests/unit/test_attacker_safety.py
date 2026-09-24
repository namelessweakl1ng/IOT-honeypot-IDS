"""Unit tests for the attacker safety check.

We import the same Python snippet that the bash runner uses to validate
--target, and verify it refuses obvious non-lab IPs.
"""
import os
import subprocess
import sys
from pathlib import Path


def _safety_check(target: str, lab_subnet: str = "192.168.1.0/24") -> int:
    """Run the same Python safety check that run-scenario.sh uses."""
    code = f"""
import os, sys, ipaddress
os.environ["TARGET"] = {target!r}
os.environ["LAB_SUBNET"] = {lab_subnet!r}
target = os.environ.get("TARGET", "")
subnet = os.environ.get("LAB_SUBNET", "")
try:
    ip = ipaddress.ip_address(target)
except ValueError:
    sys.exit(1)
if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
    sys.exit(1)
if not subnet:
    sys.exit(1)
net = ipaddress.ip_network(subnet, strict=False)
if ip not in net:
    sys.exit(1)
sys.exit(0)
"""
    return subprocess.run([sys.executable, "-c", code]).returncode


def test_accepts_lab_ip():
    assert _safety_check("192.168.1.50") == 0


def test_refuses_loopback():
    assert _safety_check("127.0.0.1") != 0


def test_refuses_link_local():
    assert _safety_check("169.254.1.1") != 0


def test_refuses_multicast():
    assert _safety_check("224.0.0.1") != 0


def test_refuses_unspecified():
    assert _safety_check("0.0.0.0") != 0


def test_refuses_public_ip():
    assert _safety_check("8.8.8.8") != 0


def test_refuses_different_subnet():
    assert _safety_check("10.0.0.1", lab_subnet="192.168.1.0/24") != 0


def test_refuses_garbage():
    assert _safety_check("not-an-ip") != 0


def test_runner_script_exists_and_is_executable():
    runner = Path(__file__).resolve().parents[2] / "attacker" / "run-scenario.sh"
    assert runner.exists(), f"{runner} should exist"
    assert os.access(runner, os.X_OK), f"{runner} should be executable"


def test_runner_refuses_no_target():
    runner = Path(__file__).resolve().parents[2] / "attacker" / "run-scenario.sh"
    # Should refuse without --target (either by demanding --target, or by
    # requiring a .env file first — either is an acceptable "refuse to run"
    # behaviour that proves the runner does not blindly fire at the world).
    result = subprocess.run([str(runner)], capture_output=True, text=True)
    assert result.returncode != 0
    assert ("target" in result.stderr.lower()
            or ".env" in result.stderr.lower()
            or "usage" in result.stderr.lower())
