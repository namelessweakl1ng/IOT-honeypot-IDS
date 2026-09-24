# End-to-end tests

E2E tests are run via the orchestration script:

```bash
./scripts/testing/run-e2e.sh --target 192.168.1.50
```

The script:

1. Verifies PC1 (ELK + API) is reachable
2. Verifies the Pi honeypot is reachable
3. Launches an attacker scenario from `attacker/`
4. Waits for telemetry to flow through Filebeat + Logstash into Elasticsearch
5. Verifies events appear in Elasticsearch
6. Verifies FastAPI `/sessions` returns at least one reconstructed session

This file is a placeholder — the actual E2E test logic lives in
`scripts/testing/run-e2e.sh` because it orchestrates multiple machines
via subprocess rather than running purely in Python.
