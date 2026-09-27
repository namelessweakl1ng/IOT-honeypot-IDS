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
| Detection latency is low/real-time | No physical latency measurement | NOT VERIFIED | Use Ã¢â‚¬Å“runtime detection pipelineÃ¢â‚¬Â only |
| The system is production ready | No production validation/security deployment evidence | NOT VERIFIED | Do not claim |
| IoT-23 is a complementary public benchmark | Official dataset card and flow adapter; actual content not present | DOCUMENTED, NOT EXECUTED | Describe intended flow benchmark; do not claim measured performance |
| IoT-23 adapter parses real IoT-23 content | Local deterministic fixture only; public download unavailable here | NOT VERIFIED AGAINST REAL ARCHIVE | State DATASET DOWNLOAD NOT RUN |
| IoT-23 model performance | No real dataset experiment artifacts | NOT VERIFIED | Do not report metrics |
| Scenario-level IoT-23 generalization | Deterministic split helper; no real execution | NOT VERIFIED | Describe protocol only |
| Pi/Filebeat/ELK controlled detection | No physical execution | NOT VERIFIED | State PHYSICAL LAB NOT RUN |
| Detection latency or Raspberry Pi resource use | No physical measurements | NOT VERIFIED | State NOT RUN; do not claim real-time or resource figures |
| Synthetic results are research evidence | Research runner rejects synthetic/demo/fixture label sources | REJECTED BY SOFTWARE CONTRACT | Synthetic is fixture/demo only |
| Current software checks pass | Python unit suite: 874 passed, 2 warnings; integration suite: 5 skipped; frontend lint/build and compose validation passed | PASS WITH SERVICE-DEPENDENT CHECKS SKIPPED | Report exact results; do not imply runtime or physical validation |
