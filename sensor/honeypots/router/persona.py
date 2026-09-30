from common.protocols import add_http_fields, http_details


class RouterPersona:
    def parse(self, data: bytes) -> dict:
        return http_details(data)

    def enrich(self, event: dict, details: dict) -> None:
        add_http_fields(event, details)

    def response(self, details: dict) -> bytes:
        return b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=TRAPSIG\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
