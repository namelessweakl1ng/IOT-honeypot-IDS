import argparse
import base64
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

import paramiko
import yaml

from .safety import validate_target

PORTS = {"ssh": 2222, "telnet": 2223, "camera": 8081, "http": 8081, "iot": 9000, "mqtt": 1883, "router": 8080}


def ssh_login(target: str, step: dict) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target, port=PORTS["ssh"], username=step["username"], password=step["password"], timeout=3, auth_timeout=3, allow_agent=False, look_for_keys=False)
        if step.get("command"):
            client.exec_command(step["command"], timeout=3)
    finally:
        client.close()


def http_request(target: str, service: str, step: dict) -> None:
    headers = {"User-Agent": "TRAPSIG-Controlled-Lab/1.0"}
    if step.get("username") is not None:
        token = base64.b64encode(f'{step["username"]}:{step["password"]}'.encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    request = Request(f'http://{target}:{PORTS[service]}{step.get("path", "/")}', headers=headers)
    try:
        urlopen(request, timeout=3).read(512)
    except Exception as exc:
        if getattr(exc, "code", None) != 401:
            raise


def mqtt_request(target: str, step: dict) -> None:
    operation = step.get("operation", "connect")
    packets = {
        "connect": b"\x10\x10\x00\x04MQTT\x04\x02\x00\x0a\x00\x04test",
        "subscribe": b"\x82\x09\x00\x01\x00\x04test\x00",
        "ping": b"\xc0\x00",
    }
    with socket.create_connection((target, PORTS["mqtt"]), timeout=3) as connection:
        connection.sendall(packets[operation])
        connection.recv(512)


def raw_request(target: str, service: str, step: dict) -> None:
    with socket.create_connection((target, PORTS[service]), timeout=3) as connection:
        connection.sendall(step.get("payload", "STATUS\\r\\n").encode().decode("unicode_escape").encode())
        connection.recv(512)


def execute(target: str, step: dict) -> None:
    service = step["service"]
    if service == "ssh":
        ssh_login(target, step)
    elif service in {"camera", "http", "router"}:
        http_request(target, service, step)
    elif service == "mqtt":
        mqtt_request(target, step)
    else:
        raw_request(target, service, step)


def run(scenario_id: str, target: str, source: str = "controlled-attacker") -> dict:
    target = validate_target(target, os.environ.get("LAB_SUBNET", ""))
    path = Path(__file__).parents[1] / "scenarios" / f"{scenario_id}.yaml"
    if not path.exists():
        raise ValueError("unknown scenario")
    scenario = yaml.safe_load(path.read_text())
    start = datetime.now(timezone.utc)
    completed = []
    for number, step in enumerate(scenario["steps"], 1):
        try:
            execute(target, step)
            completed.append({"step": number, "service": step["service"], "status": "completed"})
        except (OSError, paramiko.SSHException) as exc:
            completed.append({"step": number, "service": step["service"], "status": "completed", "response": "rejected", "detail": str(exc)})
    summary = {"run_id": "RUN-" + uuid.uuid4().hex[:12], "scenario_id": scenario_id, "start_time": start.isoformat(), "end_time": datetime.now(timezone.utc).isoformat(), "target": target, "source": source, "expected_detection": scenario["expected_detection"], "steps_completed": completed}
    output = Path(__file__).parents[1] / "runs"
    output.mkdir(exist_ok=True)
    (output / f'{summary["run_id"]}.json').write_text(json.dumps(summary, indent=2))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one bounded TRAPSIG lab scenario")
    parser.add_argument("scenario")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.scenario, args.target), indent=2))


if __name__ == "__main__":
    main()
