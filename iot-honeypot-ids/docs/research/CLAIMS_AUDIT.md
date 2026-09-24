# Claims Audit

| Claim | Evidence | Verified? | Permitted wording |
|---|---|---|---|
| TRAPSIG has a Pi -> Filebeat/Logstash -> Elasticsearch -> FastAPI -> dashboard architecture | Compose, Pi Filebeat, Logstash pipeline, FastAPI, root UI source | PARTIAL | Implemented software architecture; physical flow not validated |
| The root Next.js console is the authoritative UI | Feature coverage, root tests, route consumers | PASS for repository decision | Authoritative UI candidate/frozen UI |
| FastAPI is the domain API authority | `dashboard/api/app/main.py` routes and integrations | PASS for architecture decision | Canonical API implementation |
| The dashboard uses real backend data in LIVE mode | Root adapter forwards to FastAPI; live mode gates exist | SOFTWARE VERIFIED | Live mode is backend-backed when services are available |
| Demo data is synthetic and explicit | Mode adapter and sample import script | SOFTWARE VERIFIED | Explicit synthetic DEMO mode |
| Rules are independent ground truth | Label provenance module and tests | PASS | Rule output is detector output, not ground truth |
| v2 excludes known leaky features | Runtime feature registry and leakage audit | PASS | v2 is the leakage-safe feature vector for the known audited fields |
| Models require activation status | Model registry and tests | PASS | Activation is explicit and status-gated |
| E2E verifies event/session/detection lineage | E2E script and contract tests | SOFTWARE CONTRACT VERIFIED | Software E2E is lineage-aware when services are available |
| The physical lab delivered telemetry | No physical run in this pass | NOT VERIFIED | Do not claim |
| Detection latency is low/real-time | No physical latency measurement | NOT VERIFIED | Use “runtime detection pipeline” only |
| The system is production ready | No production validation/security deployment evidence | NOT VERIFIED | Do not claim |
| External datasets are comparable | Adapters/semantics not fully verified in this pass | NOT VERIFIED | Do not claim cross-dataset comparability |
| 869 tests pass | Current environment cannot collect missing dependencies | NOT VERIFIED | Do not claim until rerun in compatible environment |
