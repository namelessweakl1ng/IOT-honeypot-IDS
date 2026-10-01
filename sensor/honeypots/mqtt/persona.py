"""Bounded MQTT 3.1.1 honeypot persona."""

from mqtt.protocol import parse_packet


class MQTTPersona:
    def parse(self, data: bytes) -> dict:
        return parse_packet(data)

    def enrich(self, event: dict, details: dict) -> None:
        event["mqtt"] = details.copy()

    def response(self, details: dict) -> bytes:
        if details.get("malformed"):
            return b""
        operation = details.get("operation")
        if operation == "connect":
            return b"\x20\x02\x00\x00"
        if operation == "ping":
            return b"\xd0\x00"
        if operation == "subscribe":
            packet_id = details["packet_id"].to_bytes(2, "big")
            return b"\x90\x03" + packet_id + b"\x00"
        if operation == "publish" and details.get("qos") == 1 and details.get("packet_id"):
            return b"\x40\x02" + details["packet_id"].to_bytes(2, "big")
        return b""
