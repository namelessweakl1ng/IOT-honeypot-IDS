import argparse
import base64
import http.cookiejar
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

import paramiko
import yaml

from backend.app.services.scenario_contract import allowed_step_statuses

from .safety import validate_target


class ExpectedRejection(Exception):
    """The bounded action reached the service and was intentionally rejected."""


PORTS = {"ssh": 2222, "telnet": 2223, "camera": 8081, "http": 8081, "iot": 9000, "mqtt": 1883, "router": 8080}
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"


def ssh_login(target: str, step: dict) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        try:
            client.connect(
                target,
                port=PORTS["ssh"],
                username=step["username"],
                password=step["password"],
                timeout=3,
                auth_timeout=3,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.AuthenticationException as exc:
            raise ExpectedRejection(str(exc)) from exc
        commands = step.get("commands") or ([step["command"]] if step.get("command") else [])
        if commands:
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise paramiko.SSHException("SSH transport closed before command execution")
            channel = transport.open_session(timeout=3)
            try:
                # Cowrie models an interactive shell and may close an exec
                # channel before Paramiko receives the exec-request reply.
                # Use the complete shell lifecycle instead of treating that
                # protocol race as a failed command.
                channel.settimeout(3)
                channel.get_pty()
                channel.invoke_shell()
                channel.sendall(("\n".join(commands) + "\nexit\n").encode())
                channel.shutdown_write()
                while not channel.closed and channel.recv(512):
                    pass
            finally:
                channel.close()
    finally:
        client.close()


def http_request(target: str, service: str, step: dict) -> None:
    headers = {"User-Agent": USER_AGENT}
    data = None
    if step.get("auth_mode") == "form":
        data = urlencode({"username": step["username"], "password": step["password"]}).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif step.get("username") is not None:
        token = base64.b64encode(f"{step['username']}:{step['password']}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    request = Request(f"http://{target}:{PORTS[service]}{step.get('path', '/')}", data=data, headers=headers)
    try:
        if data is None:
            urlopen(request, timeout=3).read(512)
        else:
            opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            opener.open(request, timeout=3).read(512)
    except Exception as exc:
        if getattr(exc, "code", None) == 401:
            raise ExpectedRejection("HTTP 401") from exc
        raise


def _mqtt_remaining_length(length: int) -> bytes:
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        encoded.append(digit | (0x80 if length else 0))
        if not length:
            return bytes(encoded)


def _mqtt_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return len(encoded).to_bytes(2, "big") + encoded


def mqtt_packet(step: dict) -> bytes:
    operation = step.get("operation", "connect")
    if operation == "connect":
        body = b"\x00\x04MQTT\x04\x02\x00\x0a" + _mqtt_string(step.get("client_id", "mqtt-client"))
        return b"\x10" + _mqtt_remaining_length(len(body)) + body
    if operation == "subscribe":
        body = b"\x00\x01" + _mqtt_string(step.get("topic", "#")) + b"\x00"
        return b"\x82" + _mqtt_remaining_length(len(body)) + body
    if operation == "ping":
        return b"\xc0\x00"
    raise ValueError(f"unsupported MQTT operation: {operation}")


def mqtt_request(target: str, step: dict) -> None:
    with socket.create_connection((target, PORTS["mqtt"]), timeout=3) as connection:
        connection.sendall(mqtt_packet(step))
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


def run(scenario_id: str, target: str, source: str = "controlled-attacker", experiment_id: str | None = None, api_url: str | None = None) -> dict:
    target = validate_target(target, os.environ.get("LAB_SUBNET", ""))
    path = Path(__file__).parents[1] / "scenarios" / f"{scenario_id}.yaml"
    if not path.exists() or path.stem != scenario_id:
        raise ValueError("unknown scenario")
    raw = path.read_bytes()
    scenario = yaml.safe_load(raw)
    if scenario.get("id") != scenario_id:
        raise ValueError("scenario id does not match its filename")
    started = datetime.now(timezone.utc)
    steps = []
    for number, step in enumerate(scenario["steps"], 1):
        step_started = datetime.now(timezone.utc)
        status, detail = "completed", None
        try:
            execute(target, step)
        except ExpectedRejection as exc:
            status = "rejected" if "rejected" in allowed_step_statuses(step) else "failed"
            detail = str(exc)
        except Exception as exc:
            status, detail = "failed", str(exc)
        item = {
            "step": number,
            "service": step["service"],
            "started_at": step_started.isoformat(),
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "status": status,
        }
        if detail:
            item["detail"] = detail
        steps.append(item)
    failures = sum(step["status"] == "failed" for step in steps)
    overall = "completed" if failures == 0 else ("failed" if failures == len(steps) else "partial")
    summary = {
        "run_id": "RUN-" + uuid.uuid4().hex[:12],
        "experiment_id": experiment_id,
        "scenario_id": scenario_id,
        "scenario_manifest_sha256": sha256(raw).hexdigest(),
        "target": target,
        "source": source,
        "expected_detection": scenario["expected_detection"],
        "start_time": started.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall,
        "steps": steps,
    }
    output = Path(__file__).parents[1] / "runs"
    output.mkdir(exist_ok=True)
    result_path = output / f"{summary['run_id']}.json"
    result_path.write_text(json.dumps(summary, indent=2))
    if experiment_id and api_url:
        request = Request(
            f"{api_url.rstrip('/')}/experiments/{experiment_id}/ground-truth",
            data=json.dumps(summary).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urlopen(request, timeout=10).read()
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one bounded TRAPSIG lab scenario")
    parser.add_argument("scenario")
    parser.add_argument("--target", required=True)
    parser.add_argument("--source", default="controlled-attacker")
    parser.add_argument("--experiment-id")
    parser.add_argument("--api-url")
    args = parser.parse_args()
    if bool(args.experiment_id) != bool(args.api_url):
        parser.error("--experiment-id and --api-url must be supplied together")
    print(json.dumps(run(args.scenario, args.target, args.source, args.experiment_id, args.api_url), indent=2))


if __name__ == "__main__":
    main()
