import base64
import json
import os
import socketserver
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

SERVICE = os.getenv("SERVICE", "iot-service")
PROTOCOL = os.getenv("PROTOCOL", "tcp")
PORT = int(os.getenv("PORT", "9000"))
LOG = os.getenv("LOG_PATH", f"/logs/{SERVICE}.jsonl")


def http_details(data: bytes) -> dict:
    text = data.decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    method, target, *_ = (lines[0].split() + ["/", "HTTP/1.0"])[:3]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.lower().strip()] = value.strip()
    username = password = None
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("basic "):
        try:
            username, password = base64.b64decode(authorization[6:]).decode().split(":", 1)
        except (ValueError, UnicodeDecodeError):
            pass
    body = text.partition("\r\n\r\n")[2]
    form = parse_qs(body)
    username = username or form.get("username", form.get("user", [None]))[0]
    password = password or form.get("password", form.get("pass", [None]))[0]
    return {
        "method": method,
        "path": urlsplit(target).path,
        "user_agent": headers.get("user-agent"),
        "username": username,
        "password": password,
    }


def mqtt_details(data: bytes) -> dict:
    packet_type = data[0] >> 4 if data else 0
    names = {1: "connect", 3: "publish", 8: "subscribe", 10: "unsubscribe", 12: "ping"}
    return {"packet_type": packet_type, "operation": names.get(packet_type, "unknown")}


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(4096)
        details = http_details(data) if PROTOCOL == "http" else mqtt_details(data) if PROTOCOL == "mqtt" else {"payload": data.decode(errors="replace")[:1000]}
        auth = bool(details.get("username"))
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
            "category": "authentication" if auth else "web" if PROTOCOL == "http" else "network",
            "type": "info",
            "action": "login_attempt" if auth else details.get("operation", "request" if data else "connect"),
            "outcome": "failure" if auth else "unknown",
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "destination_port": PORT,
            "protocol": PROTOCOL,
            "service": SERVICE,
            "honeypot_id": SERVICE + "-01",
            "honeypot_type": SERVICE.replace("-", "_"),
            "summary": f"{SERVICE} {details.get('operation') or details.get('method') or 'interaction'}",
        }
        if PROTOCOL == "http":
            event["http"] = {"request": {"method": details["method"]}, "user_agent": details["user_agent"]}
            event["url"] = {"path": details["path"]}
        if auth:
            event["authentication"] = {"username": details["username"], "password": details["password"]}
        if PROTOCOL == "mqtt":
            event["mqtt"] = details
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, separators=(",", ":")) + "\n")
        if PROTOCOL == "http":
            response = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=TRAPSIG\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        elif PROTOCOL == "mqtt":
            response = b"\x20\x02\x00\x05" if details["operation"] == "connect" else b"\xd0\x00"
        else:
            response = b"TRAPSIG-IOT READY\r\n"
        self.request.sendall(response)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", PORT), Handler).serve_forever()
