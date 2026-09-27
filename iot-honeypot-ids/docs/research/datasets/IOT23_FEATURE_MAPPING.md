# IoT-23 feature mapping

The benchmark unit is one labeled Zeek connection flow. It is not a reconstructed honeypot session. The default classifier intentionally uses only measured numerical flow counters; it excludes identity, scenario, label, path, and endpoint fields.

| TRAPSIG feature | IoT-23 source | Transformation | Compatible? | Reason | Online/offline relevance |
|---|---|---|---|---|---|
| `duration_s` | Zeek `duration` | Numeric seconds; absent/`-` stays null | Proxy only | Connection duration is not honeypot session duration | Offline flow feature; online runtime's session duration is a distinct field |
| `bytes_in` | Zeek `orig_bytes` | Numeric originator bytes | Directional proxy | Originator direction is not inherently “into honeypot” | Offline only; runtime direction needs explicit sensor semantics |
| `bytes_out` | Zeek `resp_bytes` | Numeric responder bytes | Directional proxy | Responder direction is not inherently “out of honeypot” | Offline only |
| `packets_in` | Zeek `orig_pkts` | Numeric originator packet count | Directional proxy | Flow counter, not event count | Offline only |
| `packets_out` | Zeek `resp_pkts` | Numeric responder packet count | Directional proxy | Flow counter, not event count | Offline only |
| `source_port` | Zeek `id.orig_p` | Integer metadata | Not in default model | May encode scenario/capture artifacts | Available offline only |
| `destination_port` | Zeek `id.resp_p` | Integer metadata | Not in default model | Service/capture artifacts can leak capture identity | Available offline only |
| `protocol` | Zeek `proto` | Categorical value; any encoding must fit on train only | Not in default model | Can identify scenario/capture patterns | Available offline only |
| `event_count` | None | None | Unavailable | A flow is not a honeypot event sequence | Runtime-only concept |
| `auth_attempts` | None guaranteed in `conn.log.labeled` | None | Unavailable | Connection records do not establish application auth outcomes | Runtime-only when logs provide it |
| `command_count` | None | None | Unavailable | Shell commands are absent from connection-flow rows | Cowrie runtime only |
| `http_uri_diversity` | None guaranteed in the labeled connection log | None | Unavailable | No URI field guaranteed by the adapter input | Runtime only where application logs support it |
| `contains_path_traversal` | None | Prohibited | No | Label-derived/unavailable; would leak target behavior | Forbidden in research feature vector |
| `contains_command_injection` | None | Prohibited | No | Label-derived/unavailable | Forbidden in research feature vector |
| `contains_default_credentials` | None | Prohibited | No | Label-derived/unavailable | Forbidden in research feature vector |
| scenario, timestamp, IPs, UID, source path, labels | Zeek fields/provenance | Retain as metadata only | Not a model feature | Identity, time, path, or target labels can disclose split/answer | Used for audit/splitting only |

The current approved feature version `iot23-flow-v1` comprises `duration`, `bytes_in`, `bytes_out`, `packets_in`, and `packets_out`. The source headers are read from each Zeek file. Missing values remain null until train-only preprocessing. This vector must not be described as equivalent to the runtime honeypot-session vector.
