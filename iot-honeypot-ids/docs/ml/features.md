# Feature engineering — v1

The v1 feature vector has 25 dimensions. Each feature is documented inline
in `dashboard/ml/features.py`. This page is the human-readable summary.

## Connection / volume features

| Feature          | Type    | Rationale                                            |
|------------------|---------|------------------------------------------------------|
| `event_count`    | float   | Sessions with many events are usually suspicious    |
| `duration_s`     | float   | Long sessions often indicate interactive attackers   |
| `bytes_in_total` | float   | Bytes attacker sent us (request bodies)              |
| `bytes_out_total`| float   | Bytes we sent back (response bodies)                 |

## Authentication features

| Feature                  | Type   | Rationale                                            |
|--------------------------|--------|------------------------------------------------------|
| `auth_attempts`         | float  | Many attempts -> brute force                         |
| `auth_successes`        | float  | 1 success after many failures -> default creds      |
| `auth_failure_ratio`   | float  | Higher = more suspicious                             |
| `unique_usernames`      | float  | Many users tried -> credential attack                |
| `auth_failure_rate_per_min` | float | Pacing of failed auths                     |

## Command / execution features

| Feature             | Type   | Rationale                                            |
|---------------------|--------|------------------------------------------------------|
| `command_count`    | float  | Number of executed commands                          |
| `command_diversity`| float  | Unique command count                                 |

## HTTP features

| Feature                    | Type   | Rationale                                            |
|----------------------------|--------|------------------------------------------------------|
| `http_request_count`       | float  | Total HTTP requests in the session                   |
| `http_uri_diversity`       | float  | Unique URIs = recon signature                        |
| `http_status_4xx_ratio`    | float  | Many 4xx = probing nonexistent endpoints             |
| `http_status_5xx_ratio`    | float  | Many 5xx = injection attempts causing errors         |
| `request_rate_per_min`     | float  | High rate = automated                                |

## Network / multi-device features

| Feature            | Type   | Rationale                                            |
|--------------------|--------|------------------------------------------------------|
| `unique_protocols`| float  | SSH + HTTP + IoT in one session = multi-stage         |
| `devices_touched`  | float  | Touching multiple honeypots in one session            |
| `ports_touched`    | float  | Many distinct source ports = port-scan-like           |

## Timing features

| Feature                            | Type   | Rationale                                        |
|------------------------------------|--------|--------------------------------------------------|
| `time_between_events_mean_s`       | float  | Bot-like pacing has small, regular intervals    |
| `time_between_events_stdev_s`     | float  | Low stdev = automated; high = human              |

## Derived classification signals

| Feature                          | Type   | Rationale                                            |
|----------------------------------|--------|------------------------------------------------------|
| `contains_path_traversal`        | 0/1    | Set if any event has classification=path_traversal  |
| `contains_command_injection`     | 0/1    | Set if any event has classification=command_injection |
| `contains_default_credentials`   | 0/1    | Set if any event has classification=default_credentials |
| `is_recon_only`                  | 0/1    | Session with only GETs, no auth, no exec             |

## Why not use every available field blindly?

Spec section 19 is explicit: "Do not use every available field blindly.
Feature engineering must be explainable."

The 25 features above are all **behavioral** — they describe *what the
attacker did* without depending on values that would overfit (e.g., specific
usernames, specific URIs). This means a model trained on these features
generalizes across attackers who use different usernames but exhibit the
same behavior.

## Versioning

Feature version `v1` is the set above. If we add features later (e.g.,
PCAP-derived timing features), we bump to `v2` and re-record dataset versions.
The model registry tracks `feature_version` so we can compare apples-to-apples.
