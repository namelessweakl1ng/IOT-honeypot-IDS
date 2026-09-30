# Camera decoy

`persona.py` owns the camera's HTTP request handling and authentication challenge. Shared infrastructure in `common/` handles the socket lifecycle and JSONL telemetry. Network-facing behavior is intentionally preserved; a higher-fidelity camera persona will be implemented separately.
