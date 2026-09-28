import importlib.util
from base64 import b64encode
from pathlib import Path

spec = importlib.util.spec_from_file_location("honeypot_app", Path("sensor/honeypots/app.py"))
honeypot = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(honeypot)


def test_http_path_and_credentials_are_parsed():
    token = b64encode(b"admin:admin").decode()
    details = honeypot.http_details(f"GET /admin?tab=network HTTP/1.1\r\nAuthorization: Basic {token}\r\nUser-Agent: test\r\n\r\n".encode())
    assert details == {"method": "GET", "path": "/admin", "user_agent": "test", "username": "admin", "password": "admin"}


def test_mqtt_packets_are_classified():
    assert honeypot.mqtt_details(b"\x10\x00")["operation"] == "connect"
    assert honeypot.mqtt_details(b"\x82\x00")["operation"] == "subscribe"
