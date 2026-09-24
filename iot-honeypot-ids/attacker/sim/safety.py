"""Safety layer — every scenario passes through this before generating traffic.

Fail-closed: if ANY validation fails, raise SafetyRefusal with a clear
explanation. Never silently reinterpret an unsafe target as another target.

Constraints enforced:
  - target IP must parse correctly
  - target must be inside configured lab CIDR(s)
  - target must not be public (when require_private_target=True)
  - localhost rejected by default (when allow_localhost=False)
  - ports must be in the allowlisted set
  - scenario must be in the allowlisted set
  - limits must be sane (bounded)
  - timeout must be bounded
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List


class SafetyRefusal(Exception):
    """Raised when a safety check fails. Fail-closed — never continue."""
    pass


@dataclass
class SafetyConfig:
    """Safety configuration extracted from the experiment config."""
    allowed_cidrs: List[str]
    allowed_ports: List[int]
    allowed_scenarios: List[str]
    require_private_target: bool = True
    require_explicit_target: bool = True
    allow_localhost: bool = False
    max_connections: int = 30
    max_requests: int = 50
    max_auth_attempts: int = 10
    scenario_timeout_seconds: int = 120

    def __post_init__(self) -> None:
        # Hard safety ceilings — cannot be overridden by config
        if self.max_connections > 100:
            raise SafetyRefusal(
                f"max_connections={self.max_connections} exceeds hard safety ceiling of 100"
            )
        if self.max_requests > 200:
            raise SafetyRefusal(
                f"max_requests={self.max_requests} exceeds hard safety ceiling of 200"
            )
        if self.max_auth_attempts > 20:
            raise SafetyRefusal(
                f"max_auth_attempts={self.max_auth_attempts} exceeds hard safety ceiling of 20"
            )
        if self.scenario_timeout_seconds > 600:
            raise SafetyRefusal(
                f"scenario_timeout_seconds={self.scenario_timeout_seconds} exceeds hard safety ceiling of 600"
            )


def validate_target(target_ip: str, config: SafetyConfig) -> str:
    """Validate the target IP against all safety constraints.

    Returns the validated IP string if all checks pass.
    Raises SafetyRefusal with a clear explanation on any failure.
    """
    if not target_ip:
        raise SafetyRefusal("REFUSED: no target specified (require_explicit_target=True)")

    # Parse the IP — reject hostnames to prevent DNS-based bypass
    try:
        ip = ipaddress.ip_address(target_ip)
    except ValueError:
        raise SafetyRefusal(
            f"REFUSED: target {target_ip!r} is not a valid IP address. "
            f"Hostnames are not accepted (DNS resolution could bypass the lab CIDR check)."
        )

    # Reject loopback unless explicitly allowed
    if ip.is_loopback and not config.allow_localhost:
        raise SafetyRefusal(
            f"REFUSED: target {target_ip} is loopback. "
            f"Set safety.allow_localhost=true in config to test against localhost."
        )

    # Reject link-local / multicast / unspecified
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise SafetyRefusal(
            f"REFUSED: target {target_ip} is link-local/multicast/unspecified."
        )

    # Require private target if configured
    if config.require_private_target and not ip.is_private:
        raise SafetyRefusal(
            f"REFUSED: target {target_ip} is a public IP. "
            f"The simulator is constrained to private lab CIDRs "
            f"({', '.join(config.allowed_cidrs)})."
        )

    # Must be inside at least one allowed CIDR (unless localhost is explicitly allowed)
    if ip.is_loopback and config.allow_localhost:
        in_cidr = True  # localhost bypasses CIDR when explicitly allowed
    else:
        in_cidr = False
        for cidr_str in config.allowed_cidrs:
            try:
                net = ipaddress.ip_network(cidr_str, strict=False)
                if ip in net:
                    in_cidr = True
                    break
            except ValueError:
                raise SafetyRefusal(
                    f"REFUSED: configured allowed_cidrs contains invalid CIDR: {cidr_str!r}"
                )

    if not in_cidr:
        raise SafetyRefusal(
            f"REFUSED: target {target_ip} is outside the configured TRAPSIG lab CIDR(s) "
            f"({', '.join(config.allowed_cidrs)})."
        )

    return str(ip)


def validate_port(port: int, config: SafetyConfig) -> int:
    """Validate that a port is in the allowlisted set."""
    if port not in config.allowed_ports:
        raise SafetyRefusal(
            f"REFUSED: port {port} is not in the allowed ports list "
            f"({sorted(config.allowed_ports)}). The simulator only targets "
            f"explicitly configured TRAPSIG honeypot ports."
        )
    return port


def validate_scenario(scenario_name: str, config: SafetyConfig) -> str:
    """Validate that a scenario is in the allowlisted set."""
    if scenario_name not in config.allowed_scenarios:
        raise SafetyRefusal(
            f"REFUSED: scenario {scenario_name!r} is not in the allowed scenarios list "
            f"({sorted(config.allowed_scenarios)})."
        )
    return scenario_name


def validate_limits(config: SafetyConfig) -> SafetyConfig:
    """Validate that all limits are sane (bounded + positive)."""
    if config.max_connections <= 0:
        raise SafetyRefusal(f"REFUSED: max_connections must be positive (got {config.max_connections})")
    if config.max_requests <= 0:
        raise SafetyRefusal(f"REFUSED: max_requests must be positive (got {config.max_requests})")
    if config.max_auth_attempts <= 0:
        raise SafetyRefusal(f"REFUSED: max_auth_attempts must be positive (got {config.max_auth_attempts})")
    if config.scenario_timeout_seconds <= 0:
        raise SafetyRefusal(f"REFUSED: scenario_timeout_seconds must be positive (got {config.scenario_timeout_seconds})")
    return config
