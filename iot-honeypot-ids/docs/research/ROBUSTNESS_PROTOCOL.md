# Physical pipeline robustness protocol

These are planned fault-injection checks, not results. Run only on the isolated lab with an approved test window. Record each intervention start/end, host, software commit, relevant IDs, expected effect, observed effect, recovery duration, dropped/duplicate record counts, and whether clocks were synchronized. Do not execute more than one fault at a time.

| Check | Controlled action | Observe | Recovery evidence |
|---|---|---|---|
| Filebeat restart | Restart only `filebeat` with `docker compose restart filebeat` on the Pi | Filebeat registry/queue, Logstash reconnect, event IDs and counts | New events resume; inspect duplicates/gaps by `event_id` |
| Logstash interruption | Stop Logstash on analysis host for a bounded predeclared interval, then start it | Filebeat backoff/queue, listener 5044, Logstash health, indexed timestamps | Events received after restart; compare generated and indexed counts |
| Elasticsearch interruption | Stop Elasticsearch only for a bounded interval, then start it | Logstash output retries/dead-letter behavior, cluster health, delayed indexing | Check error index, event IDs, and queue drain |
| Network interruption | Apply a reversible firewall drop between Pi and analysis Beats port for a recorded interval | Filebeat queue and connection retry state | Restore rule and record forwarding recovery; do not infer losslessness without count evidence |
| Duplicate events | Replay one approved fixture/event with a distinct run context in the lab | Elasticsearch document IDs, event IDs, session event membership | Determine whether duplicate is deduplicated or retained; document observed policy |
| Delayed events | Hold/forward one controlled event after its original timestamp | event timestamp, `ingested_at`, session materializer time window | Verify late-arrival handling and whether existing session is updated |
| Malformed telemetry | Send a known malformed synthetic test record through an isolated test path | Logstash parse behavior and dead-letter index | Confirm malformed record is quarantined and never treated as a valid detection |

## Stop conditions

Abort on unexpected traffic outside the test host, unsafe target resolution, data loss beyond the approved test, unbounded queue growth, storage pressure, or any failure to restore the firewall/service. Retain logs and measurements only under the lab's approved retention policy. No test is considered PASS from a successful command exit alone; use the recovery evidence column.
