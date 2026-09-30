# MQTT decoy

`persona.py` owns MQTT packet classification and the minimal refusal responses; it remains a decoy, not a real broker. Shared infrastructure in `common/` handles the socket lifecycle and JSONL telemetry. Network-facing behavior is intentionally preserved; higher-fidelity broker emulation will be implemented separately.
