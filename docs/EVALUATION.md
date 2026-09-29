# Research evaluation

> Current physical Fedora/Raspberry Pi results: **NOT MEASURED**.

TRAPSIG records defensible measurements; it does not ship benchmark claims. Run every command against the private lab only and retain generated artifacts.

## Scientific outcomes and metrics

An attack is **TP** when its expected detection appears and **FN** when it does not. A control is **TN** when no linked detection appears and **FP** when any linked detection appears. Invalid ground truth, absent telemetry, settle timeout, and processing failures are **INCONCLUSIVE**, never negative evidence. Inconclusive runs are excluded from confusion-matrix denominators.

Precision is `TP/(TP+FP)`, recall is `TP/(TP+FN)`, F1 is their harmonic mean, specificity is `TN/(TN+FP)`, false-positive rate is `FP/(FP+TN)`, and accuracy is `(TP+TN)/(TP+TN+FP+FN)`. Zero denominators are null/Not measured.

Per-rule results use **positive-vs-control evaluation**: positives are only attacks whose primary expectation is that rule; negatives are valid controls. Other attacks are not negatives because secondary detections may be legitimate. Unexpected detections are reported separately, not automatically labelled false positives.

## Repetitions and configuration cohorts

Use at least five repetitions per scenario. Cohorts are SHA-256 identities over detector ruleset version, session timeout, three detector thresholds, TRAPSIG schema version, and software revision. The API/UI never combine incompatible cohorts.

Plan safely (no network action without `--execute`):

```bash
python -m evaluation.run_matrix --api-url http://localhost:8000 \
  --attacker-ip 192.168.50.10 --target-ip 192.168.50.20 --all-evaluation --repetitions 5
# Review, then repeat with --execute. Random order requires --shuffle --seed 1234.
```

The CLI uses `attacks.runner.run`, creates one experiment at a time, and records failures rather than hiding them. Local manifests contain identifiers/statuses, never credentials.

## Measurements and exports

- Evidence latency: experiment start to expected rule evidence end.
- Detection latency: experiment start to detector creation.
- Processing latency: evidence end to detector creation.
- Ingestion latency: `event.ingested - @timestamp`; negative samples are rejected.
- Observed event rate: matched events / positive runner duration. It is **not** capacity or maximum throughput.
- Step coverage: fraction of runner steps with a service/time-matched event, mapping `ssh`/`telnet` to Cowrie. It is not percentage of generated events indexed. Default tolerance is 2 seconds (`EVALUATION_STEP_TIME_TOLERANCE_SECONDS`).

Download `/evaluation/export.csv`, `/evaluation/export.json`, or generate `summary.json`, `experiments.csv`, and `report.md` in ignored `evaluation/results/<id>/`:

```bash
python -m evaluation.report --api-url http://localhost:8000
```

## Clock synchronization preflight

Run **separately on Fedora and Raspberry Pi** and retain both outputs:

```bash
python -m evaluation.preflight
```

It reports UTC, timezone, and `PASS`, `WARNING`, or `UNKNOWN`, using `timedatectl` and optionally `chronyc`. Missing optional tools do not fail the check. Ingestion latency, step coverage, and cross-host timing are only defensible when clocks are synchronized. Without records, reports state **CLOCK SYNCHRONIZATION NOT VERIFIED**.

## Physical protocols (not CI tasks)

### A. Normal repeated detection evaluation
Verify health/clocks, start samplers, review the attack plan, then execute at least five repeats. Preserve conclusive and inconclusive records; never tune thresholds between repeats.

### B. Negative-control / false-positive evaluation
Execute `--all-controls`. Controls are deliberately low intensity. MQTT may produce FP because the current detector flags any MQTT operation; do not alter the rule or hide the result.

### C. Resource use
Run locally on each host. The sampler only reads Docker stats, records explicit byte units, flushes every interval, and stops on Ctrl+C:

```bash
python -m evaluation.resources --host-label analysis --interval 1 --duration 120 --output analysis-resources.csv
python -m evaluation.resources --host-label sensor --interval 1 --duration 120 --output sensor-resources.csv
```

Physical resource values are **NOT MEASURED** until run.

### D. Backend restart idempotency
1. Export/snapshot session and detection IDs/counts.
2. Restart **only** backend: `docker compose restart backend`.
3. Wait for backend health.
4. Allow at least one processor interval.
5. Export/snapshot IDs/counts again.
6. Compare sets and verify no duplicate deterministic sessions/detections.

The evaluation API never restarts containers.

### E. Logstash interruption/recovery
1. Start resource sampler.
2. Record baseline event count.
3. Stop Logstash intentionally.
4. Run **one** bounded known scenario.
5. Restore Logstash.
6. Wait for Filebeat delivery.
7. Verify buffered telemetry arrives.
8. Record whether events were lost.
9. Inspect dead-letter count.
10. Record recovery time.

This physical test is not automated by UI or CI.

### F. Clock verification
Save preflight JSON from both hosts. Resolve warnings before timing claims.

## Limitations

- TRAPSIG is a controlled lab platform, not a production IDS.
- Results apply only to tested hardware/configuration/scenarios.
- Bounded controls are not a complete model of benign IoT traffic.
- Small samples must not be generalized broadly.
- `MQTT_PROBING` may show poor specificity because any MQTT activity triggers it.
- Physical resource values are unavailable until measured.
- Network timing depends on clock synchronization.
- CI validates software contracts, not Raspberry Pi hardware performance.

## Final physical testing checklist (not yet executed)

1. Pull latest `main` on Fedora.
2. Deploy/update Pi sensor.
3. Run preflight on Fedora.
4. Run preflight on Pi.
5. Verify NTP synchronization.
6. Start resource samplers on both machines.
7. Execute attack matrix, minimum five repeats.
8. Execute control matrix, minimum five repeats.
9. Export evaluation report.
10. Inspect INCONCLUSIVE runs.
11. Run backend restart idempotency test.
12. Run Logstash recovery test.
13. Stop resource samplers.
14. Generate final report.
15. Preserve raw CSV/JSON/Markdown artifacts for the project report.
