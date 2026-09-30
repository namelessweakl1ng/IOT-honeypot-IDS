"""Entrypoint for the small custom honeypot runtime."""

import os

from camera.persona import CameraPersona
from common.server import serve
from iot_service.persona import IoTServicePersona
from mqtt.persona import MQTTPersona
from router.persona import RouterPersona

PERSONAS = {
    "camera": CameraPersona,
    "router": RouterPersona,
    "iot-service": IoTServicePersona,
    "mqtt": MQTTPersona,
}


def select_persona(service: str):
    """Return the persona configured for *service*, or fail with a useful error."""
    try:
        return PERSONAS[service]()
    except KeyError as exc:
        choices = ", ".join(sorted(PERSONAS))
        raise ValueError(f"unknown SERVICE {service!r}; expected one of: {choices}") from exc


def main() -> None:
    service = os.getenv("SERVICE", "iot-service")
    protocol = os.getenv("PROTOCOL", "tcp")
    port = int(os.getenv("PORT", "9000"))
    log_path = os.getenv("LOG_PATH", f"/logs/{service}.jsonl")
    serve(select_persona(service), service, protocol, port, log_path)


if __name__ == "__main__":
    main()
