# IoT TCP decoy

The importable `iot_service/persona.py` module owns raw TCP payload handling and the static banner. Shared infrastructure in `common/` handles the socket lifecycle and JSONL telemetry. Network-facing behavior is intentionally preserved; a higher-fidelity command persona will be implemented separately.
