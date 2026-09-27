# Feature Provenance and Leakage Audit

## IoT-23 network-flow compatibility

IoT-23 uses the separate explicit registry at
`model-lab/model_lab/datasets/iot23_features.py`. Its initial common numeric
view uses only measured flow duration, originator/responder bytes, and packet
counts. It does not map Pi session event counts, authentication, commands, or
URI diversity. Scenario IDs, scenario-bearing paths, UIDs, addresses, ports,
protocol, timestamps, all labels, and the three label-derived Pi features are
excluded or prohibited. See `research/datasets/iot23/schema.json` and
`mappings.yaml`; the IoT-23 importer preserves source and mapped labels in
separate fields. No feature value is synthesized to fill an unavailable field.

## Overview

TRAPSIG uses two feature versions:

- **v1**: 25 features including 3 LEAKY features derived from `attack.classification`
- **v2**: 22 features (leaky ones excluded) — the default for research evaluation

## Feature Registry

### SAFE Features (v2 — default for research)

| Feature | Description | Source | Online-available? |
|---|---|---|---|
| event_count | Total events in session | event counter | YES (running count) |
| duration_s | Session duration | @timestamp range | NO (needs session end) |
| bytes_in_total | Total bytes received | http.bytes_in sum | NO (needs full session) |
| bytes_out_total | Total bytes sent | http.bytes_out sum | NO (needs full session) |
| auth_attempts | Authentication attempts | authentication.attempted count | YES |
| auth_successes | Successful authentications | authentication.success count | YES |
| auth_failure_ratio | Failures/attempts | derived from auth fields | YES |
| unique_usernames | Distinct usernames tried | authentication.username set | YES |
| command_count | Commands executed | event.type=command count | YES |
| command_diversity | Unique commands / total | derived from commands | YES |
| http_request_count | HTTP requests | http method count | YES |
| http_uri_diversity | Unique URIs | http.uri set | YES |
| http_status_4xx_ratio | 4xx responses / total | http.status | YES |
| http_status_5xx_ratio | 5xx responses / total | http.status | YES |
| unique_protocols | Distinct protocols | protocol field | YES |
| devices_touched | Distinct devices contacted | device.id set | YES |
| ports_touched | Distinct ports | destination.port set | YES |
| time_between_events_mean_s | Mean inter-event time | @timestamp deltas | NO (needs full session) |
| time_between_events_stdev_s | Std dev of inter-event time | @timestamp deltas | NO (needs full session) |
| request_rate_per_min | Requests per minute | event count / duration | NO (needs duration) |
| auth_failure_rate_per_min | Auth failures per minute | failure count / duration | NO (needs duration) |
| is_recon_only | Session is GET-only, no auth, ≥4 URIs | derived from HTTP behavior | NO (needs full session) |

### LEAKY Features (v1 only — excluded from v2)

| Feature | Why it's leaky | Derivation |
|---|---|---|
| contains_path_traversal | Derived from `attack.classification` field set by Logstash enrichment | `1 if "path_traversal" in classifications` |
| contains_command_injection | Derived from `attack.classification` | `1 if "command_injection" in classifications` |
| contains_default_credentials | Derived from `attack.classification` | `1 if "default_credentials" in classifications` |

These features encode information from the same classification logic used as the target label — using them creates circular evaluation.

## Online vs Offline Detection

### OFFLINE_SESSION (full-session classification)

All v2 features are available. The detector has access to the complete session:
- duration_s (needs session end)
- bytes_in_total / bytes_out_total (needs all events)
- time_between_events_mean/stdev (needs full timeline)
- request_rate_per_min (needs duration)
- is_recon_only (needs full session pattern)

### ONLINE_PARTIAL_SESSION (early detection)

Only features available at time T (up to the current event):
- event_count (running count)
- auth_attempts (running count)
- auth_successes (running count)
- auth_failure_ratio (running ratio)
- unique_usernames (running set)
- command_count (running count)
- http_request_count (running count)
- http_uri_diversity (running set)
- http_status_4xx_ratio (running ratio)
- http_status_5xx_ratio (running ratio)
- unique_protocols (running set)
- devices_touched (running set)
- ports_touched (running set)

Features NOT available online:
- duration_s, bytes_in_total, bytes_out_total
- time_between_events_mean/stdev
- request_rate_per_min, auth_failure_rate_per_min
- is_recon_only

**Do not claim full-session features are early-detection features.**

## Automated Leakage Guards

The `leakage_audit.py` module classifies each feature:

| Classification | Action |
|---|---|
| SAFE | Allowed in all experiments |
| SUSPECT | Allowed but flagged — verify no label correlation |
| LEAKY | REJECTED in research mode (unless `allow_leaky=True` for leakage analysis) |
| UNKNOWN | Flagged — requires manual review |

`validate_features_for_training()` raises `ValueError` if LEAKY features are present
unless `allow_leaky=True` (experimental leakage run).

## Leakage Experiment

Four conditions (methodological demonstration):

| Condition | Features | Labels | Purpose |
|---|---|---|---|
| A | Leaky (v1) | True labels | Show leakage inflation |
| B | Clean (v2) | True labels | Baseline performance |
| C | Clean (v2) | Shuffled labels | Show loss of learnability |
| D | Clean (v2) | Noisy labels (10% flipped) | Show label-noise sensitivity |
