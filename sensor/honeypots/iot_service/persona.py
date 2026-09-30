class IoTServicePersona:
    def parse(self, data: bytes) -> dict:
        return {"payload": data.decode(errors="replace")[:1000]}

    def enrich(self, event: dict, details: dict) -> None:
        return None

    def response(self, details: dict) -> bytes:
        return b"TRAPSIG-IOT READY\r\n"
