# Final demonstration guide

## Before the presentation

Verify the Fedora/laptop Compose services and Pi services are healthy; Filebeat is connected; Elasticsearch is green; the backend, frontend, and Kibana are reachable; the attacker VM address belongs to `LAB_SUBNET`; and laptop, Pi, and attacker clocks are synchronized. Record the software revision and avoid last-minute configuration changes.

## Persona demonstration

Choose one or two short examples rather than exhausting the audience: open the AsterView CV-210 camera UI or Nexora NR-1800 router UI; show the Cowrie VEG-200 shell identity; send VEC-100 `STATUS`/`INFO`; or show MQTT CONNECT/SUBSCRIBE telemetry. Explain that responses and state are bounded synthetic emulation, not real device control.

## Full attack demonstration

1. Create and start an experiment for `multi-honeypot-attack`.
2. From the isolated attacker VM run `python -m attacks.runner.run multi-honeypot-attack --target "$HONEYPOT_IP" --experiment-id "$EXPERIMENT_ID" --api-url "$API_URL"`.
3. Show the local ground-truth summary and raw/normalized events.
4. Show the reconstructed source-IP session touching all five normalized honeypot service names: `cowrie`, `camera`, `iot-service`, `mqtt`, and `router`. Explain that Cowrie represents two logical services, SSH and Telnet, which are distinguished by protocol and event telemetry.
5. Open the primary and any secondary detections; explain the rule reason and evidence IDs.
6. Finish the experiment and show its TP/FN classification and correlated IDs.
7. Use Kibana for detailed evidence exploration.

## Safety demonstration

Run the same command with `--target 8.8.8.8`. The runner must reject the public target before any network action. Explain the single private target, `LAB_SUBNET`, and fixed-port restrictions.

## Research honesty

Do not quote physical performance numbers unless the measurements have actually been collected. CI and a polished demonstration do not establish accuracy, latency, throughput, resource overhead, or recovery results.
