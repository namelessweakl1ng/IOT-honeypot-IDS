# Cross-dataset design

## Two separate benchmarks

**Benchmark A — IoT-23 public network-flow benchmark.** Zeek connection records from a public, labeled IoT network dataset evaluate flow-level classification and behavior labels.

**Benchmark B — TRAPSIG controlled Pi campaigns.** Honeypot events from controlled activity evaluate the deployed collection, event normalization, session reconstruction, detection, and lineage path.

The outputs are never concatenated into a synthetic pooled dataset. Compare only a clearly defined shared concept and disclose the different sampling unit and measurement process.

## Common abstraction and its boundary

Both domains can identify time, source/destination context, protocol or service, a flow/session grouping, and an externally defined behavior class. IoT-23 rows are Zeek flows. Pi records are honeypot events aggregated into sessions. A source/destination network flow is not equivalent to an attacker interaction session. One session may contain multiple events; network flow directions describe originator/responder, not necessarily attacker/victim roles.

The explicit compatibility table and numeric subset are in `model-lab/model_lab/datasets/iot23_features.py`. Flow duration and byte/packet totals are compatible behavioral proxies only. Authentication attempts, commands, URI diversity, honeypot type, and session event counts are **UNAVAILABLE** for IoT-23 and are not fabricated. Ports/protocols and endpoint identity may identify scenarios, so they are excluded from the default cross-scenario vector. Labels, UIDs, paths, timestamps, and scenario names are never model inputs.

Rules that inspect Pi-specific authentication, command, or URI evidence are **NOT APPLICABLE** to IoT-23. Only a separately specified network-flow rule with fields genuinely present in Zeek records can be considered supported. The classifier/anomaly benchmark does not imply that the runtime Pi rules ran on IoT-23.
