# Final demonstration guide

## Before the presentation

Verify the Fedora analysis Compose services and Pi sensor services are healthy; Filebeat can reach Logstash; Elasticsearch is healthy; the backend, frontend, and Kibana are reachable; the attacker VM can reach the fixed Pi honeypot ports; and laptop, Pi, and attacker clocks are synchronized. Record the software revision and avoid last-minute configuration changes.

The deployment is split: the Pi runs only sensor services; Fedora runs Logstash, Elasticsearch, Kibana, FastAPI, and Next.js. Kali can run in a libvirt/QEMU NAT guest. In that NAT topology, the Pi may observe Fedora's lab-interface IP as the attack source rather than Kali's guest IP. Check the actual `source.ip` in Elasticsearch before setting experiment route fields.

## Persona demonstration

Choose one or two short examples rather than exhausting the audience: open the AsterView CV-210 camera UI or Nexora NR-1800 router UI; show the Cowrie VEG-200 shell identity; send VEC-100 `STATUS`/`INFO`; or show MQTT CONNECT/SUBSCRIBE telemetry. Explain that responses and state are bounded synthetic emulation, not real device control.

## Full attack demonstration

1. In the Fedora TRAPSIG UI, create and start an experiment for `multi-honeypot-attack`. Record the generated experiment ID.
2. Confirm the attacker address to use in the experiment is the source IP actually observed in sensor telemetry. For the verified QEMU/libvirt NAT run, Kali was `192.168.122.151` but the Pi observed Fedora as `10.171.98.199`; the target Pi was `10.171.98.88`.
3. From the Kali repository checkout, activate the runner environment, set the private lab subnet, and run one explicit target:

   ```bash
   source .venv/bin/activate
   export LAB_SUBNET=10.171.98.0/24
   python -m attacks.runner.run multi-honeypot-attack \
     --target 10.171.98.88 \
     --experiment-id "$EXPERIMENT_ID" \
     --api-url http://192.168.122.1:8000
   ```

   The API URL above is an example for a Fedora backend deliberately published on the libvirt host-side address. If the backend is bound only to loopback, this URL will not work from Kali. Never widen API binding to all interfaces just to make the example work.
4. Show the runner's local ground-truth summary and raw/normalized events.
5. Show the reconstructed source-IP session touching the normalized honeypot service names: `cowrie`, `camera`, `iot-service`, `mqtt`, and `router`. Cowrie represents two logical services, SSH and Telnet, distinguished by protocol and event telemetry.
6. Finish the experiment and show its TP/FN classification or inconclusive reason, matched event/session/detection IDs, and telemetry coverage.
7. Use Kibana for detailed evidence exploration.

## Observed physical-lab smoke test (4 November 2026)

One run was completed with the following measured setup:

- Fedora analysis host: `10.171.98.199`
- Raspberry Pi sensor: `10.171.98.88`
- Kali QEMU/libvirt guest: `192.168.122.151`
- Attacker source IP observed by Pi: `10.171.98.199`
- Scenario: `multi-honeypot-attack`
- Experiment: `EXP-2F9572CFF717`
- Runner ID: `RUN-f42456a53773`
- Ground truth: valid; all seven scenario steps accepted as completed or intentionally rejected
- Correlation: telemetry settled; 14 matched events, 1 linked session, 6 linked detections
- Expected detection: `MULTI_STAGE_ATTACK`, observed
- Outcome: `TP` (true positive)
- Telemetry step coverage: `7/7` (100%)
- Runner duration: approximately 2.08 seconds
- Telemetry settle wait: approximately 3.03 seconds
- Mean event-ingestion latency: approximately 5.31 seconds; P95 approximately 9.52 seconds

These numbers describe **one successful lab run only**. They are not accuracy, throughput, latency, resource-overhead, repeatability, or general performance claims. The reported `detection_latency_seconds` and `processing_latency_seconds` were null in this run because a usable `detected_at` timestamp was not available for the matched detection. Do not present them as zero or infer them from the evidence timestamp.

The observed detection types included `MULTI_STAGE_ATTACK` plus `BRUTE_FORCE`, `DEFAULT_CREDENTIALS`, `MQTT_PROBING`, `MULTI_SERVICE_ACTIVITY`, and `RECONNAISSANCE`. The expected detection was present, so the experiment evaluated as TP.

## Safety demonstration

Run the same command with `--target 8.8.8.8`. The runner must reject the public target before any network action. Explain the single private target, `LAB_SUBNET`, and fixed-port restrictions.

## Research honesty

Do not quote physical performance numbers unless the measurements have actually been collected. A successful smoke test demonstrates one working end-to-end path; it does not establish accuracy across a cohort, latency distribution, throughput capacity, resource overhead, or recovery behavior. Use repeated, controlled experiments and the evaluation protocol before making those claims.
