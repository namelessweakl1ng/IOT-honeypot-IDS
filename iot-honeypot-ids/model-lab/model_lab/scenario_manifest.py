"""
Scenario manifest — controlled attack scenario definitions.

Each scenario defines a reproducible attack pattern that can be executed
multiple times with controlled variation to produce multiple sessions
per campaign.

The manifest is the authoritative source for:
- expected_label (ground truth when label_source=scenario)
- attack_class (MITRE family)
- target_honeypot
- expected_sessions
- variation parameters

Usage:
    from model_lab.scenario_manifest import load_manifest, get_scenario
    manifest = load_manifest()
    scenario = get_scenario("ssh-bruteforce")
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class ScenarioDef:
    """A controlled attack scenario definition."""
    id: str
    name: str
    version: str
    family: str  # e.g. "credential_access", "discovery", "execution", "collection"
    description: str
    target_honeypot: str  # cowrie-01, camera-01, iot-01
    expected_label: str  # the ground-truth label for sessions from this scenario
    attack_class: str  # MITRE-style class
    commands_or_actions: List[str] = field(default_factory=list)
    duration: str = "30s"
    expected_sessions: int = 1
    label_source: str = "scenario"
    variation_params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "family": self.family,
            "description": self.description,
            "target_honeypot": self.target_honeypot,
            "expected_label": self.expected_label,
            "attack_class": self.attack_class,
            "commands_or_actions": self.commands_or_actions,
            "duration": self.duration,
            "expected_sessions": self.expected_sessions,
            "label_source": self.label_source,
            "variation_params": self.variation_params,
        }


# The canonical scenario manifest.
# These map to the existing attacker/scenarios/*.yaml files but add
# the research metadata needed for ground-truth provenance.
SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "ssh-bruteforce",
        "name": "SSH Credential Attack",
        "version": "1.0",
        "family": "credential_access",
        "description": "Controlled SSH credential attack against the lab SSH honeypot.",
        "target_honeypot": "cowrie-01",
        "expected_label": "brute_force",
        "attack_class": "brute_force",
        "commands_or_actions": ["ssh_attempt"],
        "duration": "60s",
        "expected_sessions": 1,
        "label_source": "scenario",
        "variation_params": {
            "credentials_pool": "attacker/credentials/users.txt",
            "max_attempts": 30,
            "delay_range": [0.1, 0.5],
        },
    },
    {
        "id": "ssh-interaction",
        "name": "SSH Login + Command Interaction",
        "version": "1.0",
        "family": "execution",
        "description": "Authenticate to the SSH honeypot with default creds and execute commands.",
        "target_honeypot": "cowrie-01",
        "expected_label": "command_abuse",
        "attack_class": "command_abuse",
        "commands_or_actions": ["ssh_login", "execute_commands"],
        "duration": "45s",
        "expected_sessions": 1,
        "label_source": "scenario",
        "variation_params": {
            "credentials": [("admin", "admin")],
            "commands": ["uname -a", "ls /", "cat /etc/passwd"],
        },
    },
    {
        "id": "camera-recon",
        "name": "Camera HTTP Reconnaissance",
        "version": "1.0",
        "family": "discovery",
        "description": "GET across all simulated camera endpoints to map the attack surface.",
        "target_honeypot": "camera-01",
        "expected_label": "reconnaissance",
        "attack_class": "reconnaissance",
        "commands_or_actions": ["http_get_endpoints"],
        "duration": "30s",
        "expected_sessions": 1,
        "label_source": "scenario",
        "variation_params": {
            "paths": ["/", "/login", "/admin", "/config", "/system", "/status", "/network", "/users", "/device", "/firmware"],
        },
    },
    {
        "id": "camera-default-creds",
        "name": "Camera Default Credentials",
        "version": "1.0",
        "family": "credential_access",
        "description": "POST default credential pairs against the camera's /login endpoint.",
        "target_honeypot": "camera-01",
        "expected_label": "default_credentials",
        "attack_class": "default_credentials",
        "commands_or_actions": ["http_post_login"],
        "duration": "20s",
        "expected_sessions": 1,
        "label_source": "scenario",
        "variation_params": {
            "credentials": [("admin", "admin"), ("admin", "12345"), ("root", "root")],
        },
    },
    {
        "id": "http-enumeration",
        "name": "HTTP Enumeration & Injection",
        "version": "1.0",
        "family": "execution",
        "description": "Probe for path traversal, command injection, and exposed files.",
        "target_honeypot": "camera-01",
        "expected_label": "command_injection",
        "attack_class": "command_injection",
        "commands_or_actions": ["http_get_traversal", "http_get_injection"],
        "duration": "40s",
        "expected_sessions": 1,
        "label_source": "scenario",
        "variation_params": {
            "traversal_paths": ["/../../../etc/passwd", "/admin/../../etc/shadow"],
            "injection_paths": ["/api/exec?cmd=id", "/api/shell?c=whoami"],
        },
    },
    {
        "id": "iot-probe",
        "name": "IoT Service Probe",
        "version": "1.0",
        "family": "discovery",
        "description": "Connect to the IoT TCP service and exercise its protocol commands.",
        "target_honeypot": "iot-01",
        "expected_label": "reconnaissance",
        "attack_class": "reconnaissance",
        "commands_or_actions": ["tcp_connect", "send_commands"],
        "duration": "25s",
        "expected_sessions": 1,
        "label_source": "scenario",
        "variation_params": {
            "commands": ["PING", "STAT", "LIST", "AUTH admin admin", "CMD uname -a", "QUIT"],
        },
    },
    {
        "id": "multi-stage",
        "name": "Multi-Stage Attack Campaign",
        "version": "1.0",
        "family": "multi",
        "description": "Recon -> credential attack -> authentication -> command exec -> retrieval.",
        "target_honeypot": "camera-01",
        "expected_label": "command_injection",
        "attack_class": "multi_stage",
        "commands_or_actions": ["recon", "credential_attack", "authentication", "command_exec", "retrieval"],
        "duration": "120s",
        "expected_sessions": 3,  # Multi-stage produces multiple sessions
        "label_source": "scenario",
        "variation_params": {
            "stages": ["camera-recon", "camera-default-creds", "http-enumeration"],
        },
    },
    {
        "id": "benign-browsing",
        "name": "Benign HTTP Browsing",
        "version": "1.0",
        "family": "benign",
        "description": "Normal HTTP browsing behavior — no attack. Used as negative class.",
        "target_honeypot": "camera-01",
        "expected_label": "benign",
        "attack_class": "benign",
        "commands_or_actions": ["http_get_benign"],
        "duration": "15s",
        "expected_sessions": 1,
        "label_source": "scenario",
        "variation_params": {
            "paths": ["/", "/status"],
            "max_requests": 3,
        },
    },
    {
        "id": "path-traversal",
        "name": "Path Traversal Attack",
        "version": "1.0",
        "family": "collection",
        "description": "Attempt to read sensitive files via path traversal sequences.",
        "target_honeypot": "camera-01",
        "expected_label": "path_traversal",
        "attack_class": "path_traversal",
        "commands_or_actions": ["http_get_traversal"],
        "duration": "20s",
        "expected_sessions": 1,
        "label_source": "scenario",
        "variation_params": {
            "traversal_paths": ["/../../../etc/passwd", "/../../../etc/shadow", "/../../../etc/hosts"],
        },
    },
]


def load_manifest() -> List[ScenarioDef]:
    """Load the scenario manifest as a list of ScenarioDef objects."""
    return [ScenarioDef(**s) for s in SCENARIOS]


def get_scenario(scenario_id: str) -> Optional[ScenarioDef]:
    """Get a single scenario by ID."""
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return ScenarioDef(**s)
    return None


def get_scenarios_by_label(label: str) -> List[ScenarioDef]:
    """Get all scenarios that produce a given expected_label."""
    return [ScenarioDef(**s) for s in SCENARIOS if s["expected_label"] == label]


def get_all_labels() -> List[str]:
    """Get all unique expected_label values from the manifest."""
    return list(set(s["expected_label"] for s in SCENARIOS))


def get_all_families() -> List[str]:
    """Get all unique family values from the manifest."""
    return list(set(s["family"] for s in SCENARIOS))
