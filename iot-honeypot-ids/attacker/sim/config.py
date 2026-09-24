"""Configuration loader for the attack simulator.

Reuses the existing attacker/.env conventions (HONEYPOT_IP, LAB_SUBNET,
COWRIE_SSH_PORT, CAMERA_HTTP_PORT, IOT_SERVICE_PORT) so operators don't
need to maintain a second config file. Also supports YAML config for
the extended safety + limits options.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

from .safety import SafetyConfig, SafetyRefusal, validate_limits


@dataclass
class ExperimentConfig:
    """Full experiment configuration — target, services, limits, safety."""
    target_ip: str
    allowed_cidrs: List[str]
    ssh_port: int
    camera_port: int
    iot_port: int
    max_connections: int = 30
    max_requests: int = 50
    max_auth_attempts: int = 10
    request_delay_ms: int = 250
    scenario_timeout_seconds: int = 120
    require_private_target: bool = True
    require_explicit_target: bool = True
    allow_localhost: bool = False

    @property
    def allowed_ports(self) -> List[int]:
        return sorted({self.ssh_port, self.camera_port, self.iot_port})

    @property
    def allowed_scenarios(self) -> List[str]:
        return ["recon_basic", "ssh_banner_probe", "ssh_interaction", "web_recon", "iot_probe", "multi_stage"]

    def to_safety_config(self) -> SafetyConfig:
        return SafetyConfig(
            allowed_cidrs=self.allowed_cidrs,
            allowed_ports=self.allowed_ports,
            allowed_scenarios=self.allowed_scenarios,
            require_private_target=self.require_private_target,
            require_explicit_target=self.require_explicit_target,
            allow_localhost=self.allow_localhost,
            max_connections=self.max_connections,
            max_requests=self.max_requests,
            max_auth_attempts=self.max_auth_attempts,
            scenario_timeout_seconds=self.scenario_timeout_seconds,
        )

    def summary(self) -> str:
        lines = [
            "TRAPSIG ATTACK SIMULATOR",
            "",
            "TARGET:",
            f"  {self.target_ip}",
            "",
            "ALLOWED LAB:",
            f"  {', '.join(self.allowed_cidrs)}",
            "",
            "SERVICES:",
            f"  ssh:    port {self.ssh_port}",
            f"  camera: port {self.camera_port}",
            f"  iot:    port {self.iot_port}",
            "",
            "LIMITS:",
            f"  max_connections:        {self.max_connections}",
            f"  max_requests:           {self.max_requests}",
            f"  max_auth_attempts:      {self.max_auth_attempts}",
            f"  request_delay_ms:       {self.request_delay_ms}",
            f"  scenario_timeout_seconds: {self.scenario_timeout_seconds}",
            "",
            "SAFETY:",
            f"  require_private_target: {self.require_private_target}",
            f"  require_explicit_target: {self.require_explicit_target}",
            f"  allow_localhost:        {self.allow_localhost}",
        ]
        return "\n".join(lines)


def load_config(config_path: str | None = None) -> ExperimentConfig:
    """Load configuration from YAML, or fall back to attacker/.env conventions.

    If config_path is provided, loads from YAML. Otherwise, reads from the
    environment variables (HONEYPOT_IP, LAB_SUBNET, COWRIE_SSH_PORT, etc.)
    that the existing attacker harness already uses.
    """
    if config_path:
        return _load_from_yaml(config_path)
    return _load_from_env()


def _load_from_yaml(config_path: str) -> ExperimentConfig:
    if yaml is None:
        raise SafetyRefusal("PyYAML is required for YAML config: pip install pyyaml")
    p = Path(config_path)
    if not p.exists():
        raise SafetyRefusal(f"config file not found: {config_path}")
    with open(p) as f:
        raw = yaml.safe_load(f) or {}

    target = (raw.get("target") or {}).get("ip", "")
    lab = raw.get("lab") or {}
    cidrs = lab.get("allowed_cidrs") or ["192.168.1.0/24"]
    services = raw.get("services") or {}
    limits = raw.get("limits") or {}
    safety = raw.get("safety") or {}

    cfg = ExperimentConfig(
        target_ip=str(target),
        allowed_cidrs=[str(c) for c in cidrs],
        ssh_port=int((services.get("ssh") or {}).get("port", 2222)),
        camera_port=int((services.get("camera") or {}).get("port", 8080)),
        iot_port=int((services.get("iot") or {}).get("port", 9000)),
        max_connections=int(limits.get("max_connections", 30)),
        max_requests=int(limits.get("max_requests", 50)),
        max_auth_attempts=int(limits.get("max_auth_attempts", 10)),
        request_delay_ms=int(limits.get("request_delay_ms", 250)),
        scenario_timeout_seconds=int(limits.get("scenario_timeout_seconds", 120)),
        require_private_target=bool(safety.get("require_private_target", True)),
        require_explicit_target=bool(safety.get("require_explicit_target", True)),
        allow_localhost=bool(safety.get("allow_localhost", False)),
    )
    validate_limits(cfg.to_safety_config())
    return cfg


def _load_from_env() -> ExperimentConfig:
    """Load from the existing attacker/.env conventions."""
    target = os.environ.get("HONEYPOT_IP", "")
    subnet = os.environ.get("LAB_SUBNET", "192.168.1.0/24")
    ssh_port = int(os.environ.get("COWRIE_SSH_PORT", "2222"))
    camera_port = int(os.environ.get("CAMERA_HTTP_PORT", "8080"))
    iot_port = int(os.environ.get("IOT_SERVICE_PORT", "9000"))
    delay = float(os.environ.get("DEFAULT_DELAY", "0.2"))

    cfg = ExperimentConfig(
        target_ip=target,
        allowed_cidrs=[subnet],
        ssh_port=ssh_port,
        camera_port=camera_port,
        iot_port=iot_port,
        request_delay_ms=int(delay * 1000),
    )
    validate_limits(cfg.to_safety_config())
    return cfg
