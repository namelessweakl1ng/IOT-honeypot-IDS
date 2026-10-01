# Final honeypot personas and fidelity

This is the authoritative identity and capability reference for the feature-frozen sensor. Five honeypots expose six logical services; every identity and data value is fictional and bounded for an isolated college laboratory. Because SSH and Telnet both normalize to `service.name: cowrie`, those interactions produce five distinct normalized service names: `cowrie`, `camera`, `iot-service`, `mqtt`, and `router`.

| Service | Fictional device identity | Model / firmware | Protocol / port | Authentication | Interaction and state | Useful telemetry after normalization | Main scenarios / primary detections | Important limitations | Implementation owners |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SSH, Telnet | Velora Edge Gateway | VEG-200 / 2.7.4 | SSH 2222; Telnet 2223 | `root` / `root` | Cowrie low-interaction emulated shell; session-oriented fake filesystem and command telemetry | authentication attempts, session events, commands, source/destination and SSH/Telnet protocol | `ssh-bruteforce` → `BRUTE_FORCE`; `ssh-interaction` → `COMMAND_INTERACTION`; `telnet-auth-attempts` → `BRUTE_FORCE` | No host shell, proxy, QEMU, payload execution, or real device access | `sensor/honeypots/cowrie/`, `sensor/docker-compose.yml` |
| Camera | AsterView Network Camera | CV-210 / 2.4.7 | HTTP / 8081 | `admin` / `admin`, form and compatible Basic | Stateful bounded web persona; expiring in-memory cookie sessions; synthetic pages, status and snapshot | `http.request.method`, `http.user_agent`, `url.path`, authentication username/password and outcome | `camera-recon` → `WEB_ENUMERATION`; `camera-default-creds` → `DEFAULT_CREDENTIALS` | No camera, real stream, firmware processing, device control, or persistent state | `sensor/honeypots/camera/`, `sensor/honeypots/common/` |
| Router | Nexora Wireless Router | NR-1800 / 1.8.3 | HTTP / 8080 | `admin` / `admin`, form and compatible Basic | Stateful bounded web persona; expiring in-memory cookie sessions; synthetic network and client pages | `http.request.method`, `http.user_agent`, `url.path`, authentication username/password and outcome | `router-recon` → `WEB_ENUMERATION`; `router-default-creds` → `DEFAULT_CREDENTIALS` | No routing, DHCP/DNS, radio control, firmware processing, reboot, or persistent configuration | `sensor/honeypots/router/`, `sensor/honeypots/common/` |
| IoT TCP | Velora Edge Controller | VEC-100 / 3.2.1 | Fictional VCP/1.0-style TCP / 9000 | `admin` / `admin` through `AUTH` | Bounded line-oriented `STATUS`, `VERSION`, `INFO`, `HELP`, and `AUTH` command protocol; connection-local interaction | `iot.operation`, authentication username/password and outcome, source/destination | `iot-probe` → `RECONNAISSANCE`; `iot-default-creds` → `DEFAULT_CREDENTIALS` | No shell, GPIO, serial, device control, persistence, or arbitrary commands | `sensor/honeypots/iot_service/`, `sensor/honeypots/common/` |
| MQTT | Velora Message Gateway | VMG-100 / bounded MQTT 3.1.1 emulation | MQTT / 1883 | No real broker authentication | Bounded MQTT frame assembly and parsing; minimal replies; no persistent broker session | `mqtt.operation`, `packet_type`, `client_id`, `topic`, `packet_id`, `qos`, `flags`, `remaining_length` | `mqtt-recon`, `mqtt-auth-probe` → `MQTT_PROBING` | No delivery, subscriptions, retained messages, persistence, payload execution, or real broker authentication | `sensor/honeypots/mqtt/`, `sensor/honeypots/common/` |

Logstash converts Cowrie-native and custom JSONL records into the canonical schema before Elasticsearch indexing. Credentials above are deliberately synthetic; telemetry containing submitted credentials is research evidence and must remain confined to the lab.

## Persona-aware interaction

Camera reconnaissance probes meaningful protected AsterView endpoints without authenticating, observes their authentication challenges, and records distinct URL interactions for enumeration detection; `camera-default-creds` separately exercises successful authentication. Router reconnaissance uses public Nexora status paths. Credential scenarios submit URL-encoded HTML forms and retain Basic authentication only for compatibility. The VEC-100 scenarios use its defined line commands. MQTT scenarios encode deterministic generic client IDs and broad topic filters. Cowrie enumeration uses one authenticated interactive shell for `hostname`, `uname -a`, `id`, and `cat /etc/os-release`.

Controls (`camera-control`, `router-control`, `iot-control`, `mqtt-control`, and `ssh-control`) stay deliberately low intensity and normally have no expected detection. An attack scenario can legitimately produce secondary detections; its `expected_detection` is the primary evaluation contract.

## Where to read the code

1. `sensor/docker-compose.yml` — fixed sensor services, ports, mounts, health checks, and resource boundaries.
2. `sensor/honeypots/app.py` — explicit dispatcher selecting one custom persona.
3. `sensor/honeypots/common/server.py` — bounded connection handling, HTTP assembly, IoT line reading, MQTT frame reading, and JSONL emission.
4. `sensor/honeypots/{camera,router,iot_service,mqtt}/` and `cowrie/` — protocol parsing, fictional identity, replies, and Cowrie configuration.
5. `sensor/filebeat/filebeat.yml` — edge collection and buffered delivery.
6. `elk/logstash/pipelines/` — normalization, validation, and dead-letter routing.
7. `elk/elasticsearch/index-templates/` — canonical mappings for raw and derived evidence.
8. `backend/app/services/processor.py` and `sessionizer.py` — idempotent processing and source-IP session reconstruction.
9. `backend/app/services/detector.py` — deterministic rules, reasons, and evidence IDs.
10. `backend/app/api/experiments.py` and `evaluation/` — ground truth, metrics, timing, resources, and reports.
11. `frontend/src/lib/api.ts` and `frontend/src/app/` — typed API access and presentation pages.
12. `attacks/runner/run.py` — bounded persona-aware traffic generation and local ground truth.
