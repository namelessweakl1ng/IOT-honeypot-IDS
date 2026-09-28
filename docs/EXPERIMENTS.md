# Controlled experiments

1. State a scenario, expected rule, source, target, and target services.
2. Create and start an experiment through FastAPI.
3. Run one versioned manifest with the subnet-restricted runner.
4. Finish the experiment after telemetry arrives.
5. Inspect linked event, session, and detection IDs in TRAPSIG; use Kibana for the timeline.
6. Retain the runner JSON as ground truth outside Git and report configuration with results.

Correlation requires the experiment time window, attacker/source IP, and target IP. Detection latency is the first matching detection time minus scenario start. TP means the expected rule was observed; FN means it was not. FP analysis requires non-attack baseline windows. Precision, recall, ingestion latency, generated-versus-indexed events, Pi CPU/RAM, per-honeypot event counts, sessions per scenario, and cross-honeypot correlation are **NOT MEASURED** until physical runs produce evidence. Never invent missing values.
