# Final physical and presentation validation

Complete and retain evidence for this checklist before presentation or research measurements.

## Software validation

- [ ] GitHub CI is green for the intended revision.
- [ ] `python -m pytest -q` passes.
- [ ] `python -m ruff check backend attacks evaluation tests sensor/honeypots` passes.
- [ ] Frontend lint, type-check, and production build pass.
- [ ] Laptop and sensor Compose configurations validate.
- [ ] Backend/frontend and sensor honeypot images build.
- [ ] Elasticsearch template, Logstash pipeline, and backend integration checks pass.

## Laptop validation

- [ ] Compose reports healthy services.
- [ ] Frontend and API are reachable.
- [ ] Kibana is reachable and Elasticsearch is green.
- [ ] Logstash pipeline is running without configuration errors.

## Raspberry Pi validation

- [ ] Cowrie SSH/Telnet, camera, router, IoT, MQTT, and Filebeat are healthy.
- [ ] Filebeat is connected and its disk queue is operational.
- [ ] Container state, restart counts, CPU, and memory state are recorded.

## Manual persona smoke tests

- [ ] Cowrie: SSH with `root` / `root`; run `hostname`, `uname -a`, `id`, and `cat /etc/os-release`.
- [ ] Camera: `GET /`, form login with `admin` / `admin`, then `GET /status` with the cookie.
- [ ] Router: `GET /`, `GET /status`, then form login with `admin` / `admin`.
- [ ] IoT: send `STATUS`, `VERSION`, `INFO`, and `AUTH admin admin` as bounded lines.
- [ ] MQTT: send valid MQTT 3.1.1 `CONNECT`, `SUBSCRIBE #`, and `PINGREQ`; inspect replies and telemetry.

## Scenario validation

Run each from one explicit attacker address inside `LAB_SUBNET` and verify its primary expected detection: `camera-recon`, `camera-default-creds`, `router-recon`, `router-default-creds`, `iot-probe`, `iot-default-creds`, `mqtt-recon`, `ssh-interaction`, `ssh-bruteforce`, `cross-service-recon`, `multi-stage`, and `multi-honeypot-attack`. Confirm steps completed as intended, local ground-truth JSON exists, secondary detections remain visible, and no scenario contacted another host or port.

## Research data validation

- [ ] Minimum repetitions and controls are complete for the declared method.
- [ ] Clock-synchronization evidence and host information are saved.
- [ ] Fedora and Raspberry Pi resource CSVs are saved.
- [ ] Evaluation batch ID, software revision, schema/ruleset versions, and configuration cohort are recorded.
- [ ] Ground-truth run IDs and manifest hashes match the experiments.
- [ ] The report is generated and all `INCONCLUSIVE` runs are reviewed rather than silently excluded.
- [ ] No result is quoted unless its measurement artifact exists.
