import pytest
from backend.app.services.normalizer import normalize
@pytest.mark.parametrize("kind,service,protocol",[("camera","camera","http"),("iot_device","iot-service","tcp"),("mqtt","mqtt","mqtt"),("router","router","http")])
def test_custom_normalization(kind,service,protocol):
 raw={"timestamp":"2026-01-01T00:00:00Z","event_id":"one","source_ip":"10.0.0.2","source_port":1,"destination_port":2,"protocol":protocol,"service":service}
 event=normalize(raw,kind,f"{service}-01","pi-01"); assert event["service"]["name"]==service; assert event["event"]["id"]=="one"; assert event["trapsig"]["sensor_id"]=="pi-01"
def test_cowrie_normalization():
 event=normalize({"timestamp":"2026-01-01T00:00:00Z","eventid":"cowrie.login.failed","src_ip":"10.0.0.2","src_port":12,"dst_port":2222},"ssh_telnet","cowrie-01","pi-01")
 assert event["event"]["category"]=="authentication"; assert event["network"]["protocol"]=="ssh"
def test_malformed_rejected():
 with pytest.raises(ValueError): normalize({},"camera","camera-01","pi-01")
