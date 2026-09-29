# Reproducible experiments

TRAPSIG experiments are controlled, single-target lab runs. They are evidence records, not free-form annotations. Precision, recall, and F1 aggregation are intentionally deferred to the final evaluation work.

## Scenario catalog

`GET /scenarios` is generated from the safely parsed manifests in `attacks/scenarios`. A valid manifest has an ID matching its filename, recognized detector type, non-empty steps and target services, and matching step/service metadata. The catalog returns metadata only; credentials and step payloads are not exposed.

The exact manifest bytes are SHA-256 hashed when an experiment is created. The backend derives the expected detection and canonical targets rather than trusting browser input. At start it reads the manifest again; a changed hash returns HTTP 409 and requires a new experiment.

Canonical service mapping is: `ssh` and `telnet` → `cowrie`, `camera` and `http` → `camera`, `iot` → `iot-service`, `mqtt` → `mqtt`, and `router` → `router`.

## Lifecycle and isolation

The lifecycle is `created → running → correlating → completed`, with `created → cancelled`, `running → cancelled`, and `correlating → cancelled` also permitted. Start and completed finish responses are idempotent where safe; invalid transitions return HTTP 409. A repeated finish resumes a correlating experiment with its original `end_time`, so a transient settling failure cannot permanently lock the lab. `POST /experiments/{id}/cancel` records `cancelled_at` rather than deleting evidence. Only one experiment may be running or correlating, preventing overlapping runs from claiming the same telemetry.

Start snapshots the manifest hash, detector ruleset version, TRAPSIG schema version, and the session timeout, brute-force, web-enumeration, and multi-service thresholds. `TRAPSIG_REVISION` is recorded when supplied; otherwise software revision is null. No Git revision is invented and no secrets are captured.

## Controlled-run ground truth

The runner always writes a local JSON summary with run and optional experiment IDs, scenario and manifest hash, target/source, expected detection, run times, overall status, and per-step start/end/status. `completed` and expected authentication `rejected` actions are valid; unexpected network, protocol, or runtime errors are `failed`. Overall `completed` means no required step failed, `partial` means some did, and `failed` means all did.

Supplying both `--experiment-id` and `--api-url` posts the summary after its local file is written. The API checks experiment state, scenario/hash, target, expected detector, time plausibility, and conflicts. Reposting byte-equivalent modeled data for the same run is idempotent. Summaries describe results and do not copy scenario credentials.

**A TP or FN requires valid controlled-run ground truth.** Missing ground truth or a failed/partial run makes the result inconclusive.

## Settling and direct correlation

Finish first records `end_time` and persists `correlating`. The backend polls the count of experiment-specific events until it is unchanged for the configured quiet period, bounded by the settle timeout. The query uses occurrence time, source and destination IP, canonical `service.name` targets, and excludes internal/loopback telemetry. A timeout produces `INCONCLUSIVE / SETTLE_TIMEOUT`; it never produces an FN.

After settling, the processor runs and correlation uses a bounded Elasticsearch point-in-time (PIT) with `search_after` pagination rather than the latest N documents. Meaningful date fields are the primary sort and PIT `_shard_doc` is the mapping-independent tiebreaker; every PIT is closed in `finally`. Exact-match filters try both the typed field and its historical dynamic `.keyword` variant, allowing the same non-destructive query path to work with old and freshly templated indices. Events must match the experiment window, route, and canonical targets. Candidate sessions overlap the window and source, but are linked only by intersection with matched event IDs. Detections are linked only through those session IDs. Unrelated events in a source-IP session are not added to the experiment.

Results mean:

- **TP**: valid ground truth, settled relevant telemetry, and the expected detection.
- **FN**: valid ground truth and settled relevant telemetry, but no expected detection.
- **INCONCLUSIVE**: the run cannot support either conclusion, with a reason such as `NO_GROUND_TRUTH`, `RUNNER_FAILED`, `NO_TELEMETRY`, `SETTLE_TIMEOUT`, or `PROCESSING_ERROR`.

## Time semantics

Detection `timestamp` remains the session/evidence end time for compatibility. New records make this explicit as `evidence_end_time`; `detected_at` is the UTC wall-clock time when TRAPSIG first materialized the deterministic detection and is preserved on later processor passes.

Experiments report, only when the source timestamps exist and are non-negative:

- `evidence_latency_seconds = evidence_end_time - experiment start_time`
- `detection_latency_seconds = detected_at - experiment start_time`
- `processing_latency_seconds = detected_at - evidence_end_time`

They also retain first/last occurrence and ingestion timestamps plus telemetry settle duration. Missing or impossible timings remain null rather than being invented or silently clamped.
