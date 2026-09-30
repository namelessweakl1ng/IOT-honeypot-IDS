"""Safe, bounded parsing helpers for the protocols exposed by the personas."""

import base64
from urllib.parse import parse_qs, urlsplit


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
    form = parse_qs(text.partition("\r\n\r\n")[2])
    username = username or form.get("username", form.get("user", [None]))[0]
    password = password or form.get("password", form.get("pass", [None]))[0]
    return {"method": method, "path": urlsplit(target).path, "user_agent": headers.get("user-agent"), "username": username, "password": password}


def mqtt_details(data: bytes) -> dict:
    packet_type = data[0] >> 4 if data else 0
    names = {1: "connect", 3: "publish", 8: "subscribe", 10: "unsubscribe", 12: "ping"}
    return {"packet_type": packet_type, "operation": names.get(packet_type, "unknown")}


def add_http_fields(event: dict, details: dict) -> None:
    """Add the existing normalized HTTP and authentication structures."""
    event["http"] = {"request": {"method": details["method"]}, "user_agent": details["user_agent"]}
    event["url"] = {"path": details["path"]}
    if details.get("username"):
        event["authentication"] = {"username": details["username"], "password": details["password"]}
