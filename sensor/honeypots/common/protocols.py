"""Safe, bounded parsing helpers for the protocols exposed by the personas."""

import base64
import binascii
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
            decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass
    form = parse_qs(text.partition("\r\n\r\n")[2])
    username = username or form.get("username", form.get("user", [None]))[0]
    password = password or form.get("password", form.get("pass", [None]))[0]
    return {
        "method": method,
        "path": urlsplit(target).path,
        "user_agent": headers.get("user-agent"),
        "username": username,
        "password": password,
        "authorization": authorization,
        "cookie": headers.get("cookie", ""),
    }


def mqtt_details(data: bytes) -> dict:
    """Compatibility entry point for the MQTT persona's bounded parser."""
    from mqtt.protocol import parse_packet

    return parse_packet(data)


def add_http_fields(event: dict, details: dict) -> None:
    """Add the existing normalized HTTP and authentication structures."""
    event["http"] = {"request": {"method": details["method"]}, "user_agent": details["user_agent"]}
    event["url"] = {"path": details["path"]}
    if details.get("username"):
        event["authentication"] = {"username": details["username"], "password": details["password"]}
