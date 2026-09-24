"""web_recon — bounded HTTP reconnaissance against the camera honeypot.

Uses only endpoints appropriate to the actual camera honeypot implementation.
Does NOT brute-force arbitrary paths. Does NOT perform destructive HTTP methods.
"""
from __future__ import annotations

from .base import Scenario, ScenarioResult, StepResult

# Endpoints appropriate to the camera honeypot (matches pi/honeypots/camera/app.py)
_CAMERA_ENDPOINTS = [
    "/",
    "/login",
    "/admin",
    "/config",
    "/system",
    "/status",
    "/network",
    "/users",
    "/device",
    "/firmware",
    "/snapshot",
    "/video",
    "/api/v1",
    "/api/info",
]

_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/8.0",
    "python-requests/2.31",
]


class WebReconScenario(Scenario):
    name = "web_recon"
    behavior_class = "web_enumeration"
    description = "Bounded HTTP reconnaissance against the camera honeypot"

    def _run(self, result: ScenarioResult) -> None:
        base = f"http://{self.config.target_ip}:{self.config.camera_port}"
        endpoints = _CAMERA_ENDPOINTS[: self.config.max_requests]
        for i, path in enumerate(endpoints, 1):
            self._check_interrupted()
            url = f"{base}{path}"
            # Use urllib (no external dependency)
            status = self._http_request(url, method="GET")
            result.steps.append(StepResult(
                step=f"http_get_{i}",
                status="completed" if status else "failed",
                detail=f"GET {path} -> {status or 'no response'}",
            ))
            self._delay()

    def _dry_run_steps(self):
        steps = []
        endpoints = _CAMERA_ENDPOINTS[: self.config.max_requests]
        for i, path in enumerate(endpoints, 1):
            steps.append(StepResult(
                step=f"{i}. GET http://{self.config.target_ip}:{self.config.camera_port}{path}",
                status="dry_run",
            ))
        steps.append(StepResult(
            step=f"MAX REQUESTS: {len(endpoints)}",
            status="dry_run",
        ))
        return steps
