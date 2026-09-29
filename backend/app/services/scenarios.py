"""Validated scenario catalog backed by the repository YAML manifests."""

from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from ..config import get_settings
from .detector import SUPPORTED_DETECTION_TYPES

SERVICE_TO_HONEYPOT = {
    "ssh": "cowrie",
    "telnet": "cowrie",
    "camera": "camera",
    "http": "camera",
    "iot": "iot-service",
    "mqtt": "mqtt",
    "router": "router",
}


class ScenarioCatalogError(ValueError):
    pass


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    description: str
    expected_detection: str
    severity: str
    target_honeypots: tuple[str, ...]
    target_services: tuple[str, ...]
    step_count: int
    manifest_sha256: str

    def public_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["target_honeypots"] = list(self.target_honeypots)
        result["target_services"] = list(self.target_services)
        return result


class ScenarioCatalog:
    def __init__(self, directory: str | Path | None = None):
        self.directory = Path(directory or get_settings().scenario_dir)

    def load(self) -> dict[str, Scenario]:
        result: dict[str, Scenario] = {}
        for path in sorted(self.directory.glob("*.yaml")):
            raw = path.read_bytes()
            try:
                manifest = yaml.safe_load(raw)
            except yaml.YAMLError as exc:
                raise ScenarioCatalogError(f"invalid YAML in {path.name}: {exc}") from exc
            if not isinstance(manifest, dict):
                raise ScenarioCatalogError(f"{path.name}: manifest must be an object")
            scenario = self._validate(path, raw, manifest)
            if scenario.id in result:
                raise ScenarioCatalogError(f"duplicate scenario id: {scenario.id}")
            result[scenario.id] = scenario
        return result

    def get(self, scenario_id: str) -> Scenario:
        try:
            return self.load()[scenario_id]
        except KeyError as exc:
            raise ScenarioCatalogError(f"unknown scenario: {scenario_id}") from exc

    @staticmethod
    def _validate(path: Path, raw: bytes, data: dict[str, Any]) -> Scenario:
        for field in ("id", "name", "description", "expected_detection"):
            if not isinstance(data.get(field), str) or not data[field].strip():
                raise ScenarioCatalogError(f"{path.name}: {field} is required")
        if data["id"] != path.stem:
            raise ScenarioCatalogError(f"{path.name}: id must match filename")
        if data["expected_detection"] not in SUPPORTED_DETECTION_TYPES:
            raise ScenarioCatalogError(f"{path.name}: unknown expected detection")
        services = data.get("target_services")
        steps = data.get("steps")
        if not isinstance(services, list) or not services:
            raise ScenarioCatalogError(f"{path.name}: target_services must be non-empty")
        if not isinstance(steps, list) or not steps:
            raise ScenarioCatalogError(f"{path.name}: steps must be non-empty")
        step_services = []
        for step in steps:
            service = step.get("service") if isinstance(step, dict) else None
            if service not in SERVICE_TO_HONEYPOT:
                raise ScenarioCatalogError(f"{path.name}: unknown step service {service!r}")
            step_services.append(service)
        if any(service not in SERVICE_TO_HONEYPOT for service in services):
            raise ScenarioCatalogError(f"{path.name}: unknown target service")
        if set(services) != set(step_services):
            raise ScenarioCatalogError(f"{path.name}: target_services do not match steps")
        honeypots = tuple(dict.fromkeys(SERVICE_TO_HONEYPOT[s] for s in step_services))
        return Scenario(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            expected_detection=data["expected_detection"],
            severity=str(data.get("severity", "unknown")),
            target_honeypots=honeypots,
            target_services=tuple(services),
            step_count=len(steps),
            manifest_sha256=sha256(raw).hexdigest(),
        )
