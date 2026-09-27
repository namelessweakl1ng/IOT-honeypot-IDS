# Demonstration guide

The single entry point is:

```bash
See the repository-root [DEMO.md](../../../DEMO.md) for the single authoritative demonstration procedure. This historical note is not an alternate procedure.
```

## What the demo does

```
SYSTEM CHECK
     ↓
HONEYPOT CHECK
     ↓
ELK CHECK
     ↓
ATTACK
     ↓
TELEMETRY
     ↓
SESSION RECONSTRUCTION
     ↓
ML DETECTION
     ↓
UNKNOWN PATTERN
     ↓
LABEL
     ↓
RETRAIN
     ↓
EVALUATE
     ↓
REPLAY
     ↓
FINAL DETECTION
```

## Stage-by-stage

### Stage 1: System check
- Verify PC1 containers are healthy (ES, Logstash, Kibana, API)
- Verify Pi honeypots are running (`./scripts/status.sh` from the Pi side)
- Verify PC2 attacker tooling is available

### Stage 2: Honeypot check
- Open a browser to the camera honeypot URL: `http://<PI_IP>:8080/`
- Confirm you see the fake login page

### Stage 3: ELK check
- Open Kibana: `http://<PC1_IP>:5601`
- Confirm the `honeypot-events-*` index pattern exists
- Confirm events appear when you click around the camera honeypot

### Stage 4: Attack
- From PC2: `./run-scenario.sh --target <PI_IP> --scenario ssh-bruteforce`

### Stage 5: Telemetry
- Watch events arrive in Kibana Discover in near-real-time
- Verify Filebeat is shipping (`./scripts/status.sh` on the Pi)

### Stage 6: Session reconstruction
- Open the FastAPI: `http://<PC1_IP>:8000/sessions`
- Or in the React dashboard: Sessions tab
- Click a session to see its full event timeline

### Stage 7: ML detection (known)
- Trigger training if no model exists yet:
  `python -m model_lab.train --algorithm random_forest --seed 42`
- Run replay to detect: `python -m model_lab.replay --scenario camera-recon --target <PI_IP> --model-id model-v001`

### Stage 8: Unknown pattern
- Run a scenario whose class was NOT in the training data
- The IsolationForest flags the session as anomalous

### Stage 9: Label
- In Kibana, find the session
- Use `POST /sessions/{id}/label` (planned — for now, manually add a row to the dataset CSV)

### Stage 10: Retrain
- `python -m model_lab.train --algorithm random_forest --seed 42 --model-id model-v002`

### Stage 11: Evaluate
- `python -m model_lab.evaluate --model-id model-v002`

### Stage 12: Replay
- `python -m model_lab.replay --scenario <same-as-stage-8> --target <PI_IP> --model-id model-v002`

### Final detection
Show:
```
BEFORE (model-v001)
  Unknown / anomaly
  score: X

AFTER RETRAINING (model-v002)
  Recognized attack class
  confidence: Y
```

All values come from the actual system — no fake metrics.
