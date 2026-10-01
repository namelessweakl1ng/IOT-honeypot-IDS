"""Small, allocation-bounded MQTT 3.1.1 packet parser."""

PACKET_NAMES = {
    1: "connect",
    2: "connack",
    3: "publish",
    4: "puback",
    8: "subscribe",
    10: "unsubscribe",
    12: "ping",
    14: "disconnect",
}


def _utf8(payload: bytes, offset: int) -> tuple[str, int] | None:
    if offset + 2 > len(payload):
        return None
    length = int.from_bytes(payload[offset : offset + 2], "big")
    end = offset + 2 + length
    if end > len(payload):
        return None
    try:
        return payload[offset + 2 : end].decode("utf-8"), end
    except UnicodeDecodeError:
        return None


def parse_packet(data: bytes) -> dict:
    """Parse one already-bounded read and report malformed input as data."""
    if not data:
        return {"packet_type": 0, "flags": 0, "operation": "unknown", "malformed": True, "error": "empty packet"}

    packet_type, flags = data[0] >> 4, data[0] & 0x0F
    result = {"packet_type": packet_type, "flags": flags, "operation": PACKET_NAMES.get(packet_type, "unknown")}
    multiplier = 1
    remaining_length = 0
    index = 1
    for byte_number in range(4):
        if index >= len(data):
            return {**result, "malformed": True, "error": "truncated remaining length"}
        encoded = data[index]
        index += 1
        remaining_length += (encoded & 0x7F) * multiplier
        if not encoded & 0x80:
            break
        multiplier *= 128
    else:
        return {**result, "malformed": True, "error": "malformed remaining length"}

    result["remaining_length"] = remaining_length
    if remaining_length > len(data) - index:
        return {**result, "malformed": True, "error": "truncated payload"}
    if remaining_length != len(data) - index:
        return {**result, "malformed": True, "error": "trailing packet data"}
    payload = data[index : index + remaining_length]

    if packet_type == 1:
        _parse_connect(payload, result)
        if flags != 0:
            result["malformed"] = True
    elif packet_type == 3:
        _parse_publish(payload, result)
    elif packet_type == 8:
        _parse_subscribe(payload, result)
        if flags != 2:
            result["malformed"] = True
    elif packet_type in {12, 14} and (flags != 0 or payload):
        result["malformed"] = True
    return result


def _parse_connect(payload: bytes, result: dict) -> None:
    protocol = _utf8(payload, 0)
    if protocol is None or protocol[1] + 4 > len(payload):
        result["malformed"] = True
        return
    result["protocol_name"], offset = protocol
    result["protocol_level"] = payload[offset]
    connect_flags = payload[offset + 1]
    result.update(
        connect_flags=connect_flags,
        keep_alive=int.from_bytes(payload[offset + 2 : offset + 4], "big"),
        username_present=bool(connect_flags & 0x80),
        password_present=bool(connect_flags & 0x40),
    )
    client = _utf8(payload, offset + 4)
    if client is None:
        result["malformed"] = True
        return
    result["client_id"] = client[0]
    if result["protocol_name"] != "MQTT" or result["protocol_level"] != 4 or connect_flags & 0x01:
        result["malformed"] = True


def _parse_subscribe(payload: bytes, result: dict) -> None:
    if len(payload) < 5:
        result["malformed"] = True
        return
    result["packet_id"] = int.from_bytes(payload[:2], "big")
    topic = _utf8(payload, 2)
    if topic is None or topic[1] >= len(payload):
        result["malformed"] = True
        return
    result["topic"] = topic[0]
    result["requested_qos"] = payload[topic[1]]
    if result["packet_id"] == 0 or result["requested_qos"] != 0 or topic[1] + 1 != len(payload):
        result["malformed"] = True


def _parse_publish(payload: bytes, result: dict) -> None:
    result["qos"] = (result["flags"] >> 1) & 0x03
    topic = _utf8(payload, 0)
    if topic is None or not topic[0] or result["qos"] == 3:
        result["malformed"] = True
        return
    result["topic"] = topic[0]
    offset = topic[1]
    if result["qos"] > 0:
        if offset + 2 > len(payload):
            result["malformed"] = True
            return
        result["packet_id"] = int.from_bytes(payload[offset : offset + 2], "big")
        if result["packet_id"] == 0:
            result["malformed"] = True
