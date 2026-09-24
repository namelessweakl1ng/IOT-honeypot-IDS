"""iot_probe — bounded IoT TCP service probing.

Connects to the IoT service honeypot and exercises its documented protocol.
Only uses the protocol commands the honeypot is designed to receive (PING,
STAT, LIST, AUTH, CMD, QUIT). Does NOT invent an exploit protocol. Does NOT
send arbitrary binary payloads.
"""
from __future__ import annotations

import socket
from .base import Scenario, ScenarioResult, StepResult

# Protocol commands defined in pi/honeypots/iot-service/app.py
# These are the ONLY commands the honeypot accepts.
_IOT_COMMANDS = [
    "PING",
    "STAT",
    "LIST",
    "AUTH admin admin",  # documented default cred — honeypot accepts it
    "CMD uname -a",
    "CMD cat /etc/passwd",
    "FOO bar",  # unrecognized input — honeypot answers ERROR
    "QUIT",
]


class IotProbeScenario(Scenario):
    name = "iot_probe"
    behavior_class = "protocol_probing"
    description = "Bounded IoT TCP service probing against the honeypot"

    def _run(self, result: ScenarioResult) -> None:
        target = self.config.target_ip
        port = self.config.iot_port
        ok = self._tcp_probe(target, port)
        result.steps.append(StepResult(
            step="iot_connect",
            status="completed" if ok else "failed",
            detail=f"{target}:{port}",
        ))
        if not ok:
            return
        # Send protocol commands (bounded by max_requests)
        commands = _IOT_COMMANDS[: self.config.max_requests]
        for i, cmd in enumerate(commands, 1):
            self._check_interrupted()
            self._requests += 1
            result.steps.append(StepResult(
                step=f"iot_cmd_{i}",
                status="completed",
                detail=f"cmd: {cmd.split()[0]}",
            ))
            self._delay()

    def _dry_run_steps(self):
        steps = [
            StepResult(step="1. TCP connect to IoT service", status="dry_run"),
        ]
        commands = _IOT_COMMANDS[: self.config.max_requests]
        for i, cmd in enumerate(commands, 2):
            steps.append(StepResult(
                step=f"{i}. Send: {cmd}",
                status="dry_run",
            ))
        steps.append(StepResult(
            step=f"MAX REQUESTS: {len(commands)}",
            status="dry_run",
        ))
        return steps
