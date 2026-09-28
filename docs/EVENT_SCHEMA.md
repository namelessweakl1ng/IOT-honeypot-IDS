# Canonical event schema

Every `trapsig-events-*` document is ECS-inspired and contains:

```json
{"@timestamp":"2026-01-01T12:00:00Z","event":{"id":"unique","category":"authentication","type":"info","action":"login_attempt","outcome":"failure"},"source":{"ip":"192.0.2.20","port":41234},"destination":{"ip":"192.0.2.10","port":2222},"network":{"transport":"tcp","protocol":"ssh"},"service":{"name":"cowrie"},"honeypot":{"id":"cowrie-01","type":"ssh_telnet"},"observer":{"name":"trapsig-pi","type":"honeypot_sensor"},"trapsig":{"sensor_id":"pi-01"},"message":"Failed login"}
```

`event.category` is one of `authentication`, `network`, `web`, `process`, or `session`; `event.type` uses `connection`, `start`, `end`, `info`, or `error`; outcome is `success`, `failure`, or `unknown`. Protocol details belong only below controlled `ssh`, `http`, `mqtt`, `cowrie`, `authentication`, `process`, or `url` objects. IDs must be stable and unique. Times are UTC ISO-8601. Parse failures retain the original record in `trapsig-dead-letter-*`.

Authentication events may contain `authentication.username` and `authentication.password` from deliberately submitted honeypot credentials. HTTP requests use `http.request.method`, `http.user_agent`, and `url.path`. MQTT records use `mqtt.operation` and `mqtt.packet_type`. These controlled namespaces are retained through Logstash so session and rule processing consumes the exact indexed contract.
