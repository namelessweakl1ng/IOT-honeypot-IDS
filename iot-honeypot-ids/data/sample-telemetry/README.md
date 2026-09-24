# Sample telemetry — SYNTHETIC

Clearly labeled `SYNTHETIC` / `REPLAY` events used by the offline
development mode (`scripts/development/import-sample-data.sh`).

Every event in this directory carries:

```json
"labels": { "source": "SYNTHETIC", "campaign_id": "syn-campaign-..." },
"tags": ["SYNTHETIC", "REPLAY"]
```

So the platform can never confuse these with real captures.

## Files

| File                      | Scenario                                       |
|---------------------------|------------------------------------------------|
| `camera-recon.jsonl`     | 5 GET events across camera endpoints           |
| `ssh-bruteforce.jsonl`   | 7 SSH auth attempts against Cowrie             |
