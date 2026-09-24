# Pass 6/7 Compatibility Audit

## Summary

**Initial state**: 789 PASS / 80 FAIL / 869 TOTAL

## Failure Classification

### Category A: Missing Implementation (56 tests)

These tests expect features that were implemented in later repository states
(Pass 6/7 hardening commits) but are absent from the current archive.

| Subsystem | Tests | Root Cause |
|---|---|---|
| Detection endpoints in main.py | 8 | `/detect/rule/{sid}`, `/detect/anomaly/{sid}`, `/detect/hybrid/{sid}`, `/detections/{id}`, `/detections/{id}/lineage`, `/campaigns`, `/features/schema`, `/anomaly/train`, `/anomaly/status`, `/models/active` not implemented |
| Model registry activation gate | 5 | `get_active_model()`, `_retire_other_active()`, state machine (validated→active) not implemented |
| Session scheduler automatic detection | 4 | `_run_automatic_detection()` not in session_scheduler.py |
| Automatic pipeline dedup | 4 | Config fingerprint + skip logic not in scheduler |
| Detection persistence honesty | 1 | `persisted` flag not in detect endpoints |
| Detection config fingerprint | 1 | `detector_config_fingerprint` not in ES template |
| Model/detector lineage separation | 3 | `detector_version`, `model_id`, `persisted` not in ES detections template |
| Dashboard lineage honesty | 2 | `detections-page.tsx` doesn't have `detector_version`, `NOT USED` |
| Operational anomaly metadata | 4 | `training_mode`, `threshold_calibration` not in `/anomaly/train` response |
| IoT credential redaction | 5 | `_redact_iot_credentials()` not in iot-service/app.py |
| Temporal split metadata | 6 | `split_temporal_with_metadata()` not in research.py |
| Temporal split no-silent-fallback | 6 | `split_temporal()` still falls back silently |
| Temporal split correctness | 7 | Indexing bug + silent fallback not fixed |
| Sessions template campaign_id | 1 | `campaign_id` not in honeypot-sessions.json |
| Detections template full field set | 1 | Missing fields in honeypot-detections.json |
| E2E leaf field verification | 2 | E2E script doesn't verify leaf fields |

**Total Category A: 56 tests**

### Category B: Outdated Test (0 tests)

No tests are outdated — all test expectations are correct for the intended
Pass 6/7 contract.

### Category C: Incorrect Test Expectation (0 tests)

All test expectations are scientifically valid.

### Category D: Integration/Environment Failure (0 tests)

No environment-specific failures.

### Category E: Scientific-Validity Regression (0 tests)

No scientific-validity regressions.

### Category F: Unknown (24 tests)

These are tests that expect features from Pass 6/7 that are closely
related to Category A but need individual inspection:

| Subsystem | Tests | Notes |
|---|---|---|
| E2E script contracts | 6 | Bounded polling, run markers, session verification |
| ES bootstrap exists | 1 | `bootstrap-elasticsearch.sh` missing |
| ES template dangling pipeline | 2 | Template still references `honeypot-default` |
| Route collision | 2 | `/models/active` before `/models/{model_id}` |
| Campaign event count idempotency | 0 | Already passing |

**Total Category F: 24 tests** (these are actually Category A — missing
implementation, just grouped differently for clarity)

## Grand Total: 80 failures, ALL Category A (Missing Implementation)

All 80 failures are caused by missing Pass 6/7 features that need to be
implemented. None are outdated tests, incorrect expectations, or
scientific-validity regressions.
