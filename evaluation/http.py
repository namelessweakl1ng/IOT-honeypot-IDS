import json
from urllib.request import Request, urlopen


def request_json(url: str, method: str = "GET", data: dict | None = None):
    body = json.dumps(data).encode() if data is not None else None
    request = Request(url, data=body, method=method, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=90) as response:
        return json.loads(response.read())


def request_text(url: str) -> str:
    with urlopen(url, timeout=90) as response:
        return response.read().decode()
