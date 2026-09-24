"""Scenario base + implementations.

Each scenario:
  - Validates via the safety layer before generating any traffic
  - Supports dry-run (no network connections)
  - Records every action to the manifest
  - Respects global limits (max_connections, max_requests, max_auth_attempts)
  - Stops cleanly on SIGINT/SIGTERM
  - Uses only the configured TRAPSIG honeypot ports
"""
from __future__ import annotations

import abc
import os
import random
import signal
import socket
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..config import ExperimentConfig
from ..safety import SafetyRefusal, validate_port, validate_scenario, validate_target


@dataclass
class StepResult:
    """Result of a single scenario step."""
    step: str
    status: str  # "completed" | "failed" | "skipped" | "interrupted"
    detail: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class ScenarioResult:
    """Result of a complete scenario run."""
    scenario: str
    status: str  # "completed" | "interrupted" | "failed" | "timeout"
    steps: List[StepResult] = field(default_factory=list)
    statistics: Dict[str, int] = field(default_factory=lambda: {
        "connections": 0, "requests": 0, "auth_attempts": 0
    })
    started_at: str = ""
    ended_at: str = ""
    error: str = ""


class _Interrupted(Exception):
    """Internal: raised when SIGINT/SIGTERM is received."""
    pass


class _SharedBudget:
    """Shared execution budget for multi-stage runs.

    Ensures that ALL child stages collectively stay within the configured
    global limits (max_connections, max_requests, max_auth_attempts).
    Without this, each child stage would reset its own counters and the
    total could exceed the configured ceiling.
    """
    def __init__(self, max_connections: int, max_requests: int, max_auth_attempts: int) -> None:
        self.max_connections = max_connections
        self.max_requests = max_requests
        self.max_auth_attempts = max_auth_attempts
        self.connections = 0
        self.requests = 0
        self.auth_attempts = 0

    def can_connect(self) -> bool:
        return self.connections < self.max_connections

    def can_request(self) -> bool:
        return self.requests < self.max_requests

    def can_auth(self) -> bool:
        return self.auth_attempts < self.max_auth_attempts


class Scenario(abc.ABC):
    """Base class for all attack scenarios.

    Subclasses implement _run() — they receive a context with the config,
    a random generator (seeded), and helper methods that respect limits.

    GLOBAL BUDGET (final hardening):
      When a multi-stage scenario creates child scenarios, it passes a
      shared _SharedBudget object so that ALL children collectively stay
      within the configured global limits. Without this, each child would
      reset its own counters and the total could exceed the ceiling.
    """

    name: str = ""
    behavior_class: str = "reconnaissance"
    description: str = ""

    def __init__(self, config: ExperimentConfig, seed: int = 42, profile: str = "normal",
                 budget: _SharedBudget | None = None) -> None:
        self.config = config
        self.rng = random.Random(seed)
        self.seed = seed
        self.profile = profile
        self._interrupted = False
        self._connections = 0
        self._requests = 0
        self._auth_attempts = 0
        # Shared budget — if provided (by multi_stage), child scenarios
        # check against this instead of their own local counters.
        self._budget = budget or _SharedBudget(
            max_connections=config.max_connections,
            max_requests=config.max_requests,
            max_auth_attempts=config.max_auth_attempts,
        )

    @property
    def safety_config(self) -> Any:
        from ..safety import SafetyConfig
        return self.config.to_safety_config()

    def run(self, dry_run: bool = False) -> ScenarioResult:
        """Run the scenario with full safety validation + manifest tracking."""
        # Pre-flight safety validation
        validate_target(self.config.target_ip, self.safety_config)
        validate_scenario(self.name, self.safety_config)

        result = ScenarioResult(
            scenario=self.name,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        )

        # Install signal handlers for clean interruption
        old_sigint = signal.signal(signal.SIGINT, self._handle_signal)
        old_sigterm = signal.signal(signal.SIGTERM, self._handle_signal)
        try:
            if dry_run:
                result.status = "dry_run"
                result.steps = self._dry_run_steps()
            else:
                self._run(result)
                if self._interrupted:
                    result.status = "interrupted"
                else:
                    result.status = "completed"
        except _Interrupted:
            result.status = "interrupted"
        except Exception as exc:
            result.status = "failed"
            result.error = f"{exc.__class__.__name__}: {exc}"
        finally:
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)
            result.ended_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            result.statistics = {
                "connections": self._connections,
                "requests": self._requests,
                "auth_attempts": self._auth_attempts,
            }

        return result

    def _handle_signal(self, signum: int, frame: Any) -> None:
        self._interrupted = True

    def _check_interrupted(self) -> None:
        if self._interrupted:
            raise _Interrupted()

    def _delay(self) -> None:
        """Bounded delay between operations."""
        self._check_interrupted()
        base_ms = self.config.request_delay_ms
        if self.profile == "fast":
            delay = max(base_ms // 4, 50) / 1000.0
        elif self.profile == "slow":
            delay = (base_ms * 2 + self.rng.randint(0, 500)) / 1000.0
        else:  # normal
            delay = (base_ms + self.rng.randint(0, 100)) / 1000.0
        time.sleep(min(delay, 5.0))  # hard cap at 5s

    def _tcp_probe(self, host: str, port: int, timeout: float = 3.0) -> bool:
        """Bounded TCP connectivity check. Returns True if connect succeeded.
        Checks the SHARED budget — multi-stage runs cannot exceed global limits."""
        self._check_interrupted()
        if not self._budget.can_connect():
            return False
        validate_port(port, self.safety_config)
        self._budget.connections += 1
        self._connections += 1
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _http_request(self, url: str, method: str = "GET", timeout: float = 5.0) -> Optional[int]:
        """Bounded HTTP request. Returns status code or None on failure.
        Checks the SHARED budget — multi-stage runs cannot exceed global limits."""
        self._check_interrupted()
        if not self._budget.can_request():
            return None
        self._budget.requests += 1
        self._requests += 1
        try:
            req = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status
        except Exception:
            return None

    @abc.abstractmethod
    def _run(self, result: ScenarioResult) -> None:
        """Implement the scenario. Override in subclasses."""
        ...

    def _dry_run_steps(self) -> List[StepResult]:
        """Default dry-run: show the steps the scenario WOULD take."""
        return [
            StepResult(step=f"{self.name}_dry_run", status="dry_run",
                       detail="no network connections generated"),
        ]
