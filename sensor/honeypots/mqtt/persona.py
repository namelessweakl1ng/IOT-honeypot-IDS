from common.protocols import mqtt_details


class MQTTPersona:
    def parse(self, data: bytes) -> dict:
        return mqtt_details(data)

    def enrich(self, event: dict, details: dict) -> None:
        event["mqtt"] = details

    def response(self, details: dict) -> bytes:
        return b"\x20\x02\x00\x05" if details["operation"] == "connect" else b"\xd0\x00"
