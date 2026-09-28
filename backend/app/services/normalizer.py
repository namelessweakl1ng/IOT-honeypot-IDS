from hashlib import sha256
from typing import Any

def normalize(raw: dict[str, Any], honeypot_type: str, honeypot_id: str, sensor_id: str) -> dict[str, Any]:
    """Reference implementation of the Logstash canonical mapping, used by smoke tests."""
    cowrie=honeypot_type=="ssh_telnet"
    timestamp=raw.get("timestamp") or raw.get("@timestamp")
    source_ip=raw.get("src_ip") if cowrie else raw.get("source_ip")
    if not timestamp or not source_ip: raise ValueError("timestamp and source IP are required")
    identifier=raw.get("eventid") if cowrie else raw.get("event_id")
    identifier=identifier or sha256(f"{timestamp}|{source_ip}|{raw}".encode()).hexdigest()
    service="cowrie" if cowrie else raw.get("service")
    protocol=("telnet" if raw.get("dst_port")==2223 else "ssh") if cowrie else raw.get("protocol")
    category="authentication" if cowrie and "login" in raw.get("eventid","") else raw.get("category","network")
    return {"@timestamp":timestamp,"event":{"id":identifier,"category":category,"type":raw.get("type","info"),"action":"login_attempt" if category=="authentication" else raw.get("action","observe"),"outcome":raw.get("outcome","unknown")},"source":{"ip":source_ip,"port":raw.get("src_port") or raw.get("source_port")},"destination":{"ip":raw.get("destination_ip","sensor"),"port":raw.get("dst_port") or raw.get("destination_port")},"network":{"transport":"tcp","protocol":protocol},"service":{"name":service},"honeypot":{"id":honeypot_id,"type":honeypot_type},"observer":{"name":"trapsig-pi","type":"honeypot_sensor"},"trapsig":{"sensor_id":sensor_id},"message":raw.get("summary") or raw.get("message",identifier)}
