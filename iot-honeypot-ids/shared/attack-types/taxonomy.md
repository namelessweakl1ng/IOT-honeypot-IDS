# Attack-type taxonomy

This file is the canonical list of attack classifications used by the
platform. It is referenced by:

- The rule engine (`dashboard/ml/rules.py`)
- The Logstash enrichment (`dashboard/logstash/pipelines/beats.conf`)
- The ML label space (`model-lab/model_lab/datasets/bootstrap.py`)
- The Kibana dashboards

## Classifications

| Classification          | Description                                                | MITRE (when applicable)                 |
|-------------------------|------------------------------------------------------------|------------------------------------------|
| `brute_force`           | Many auth failures across many usernames                   | T1110 Brute Force                        |
| `default_credentials`   | Successful auth using known default creds                 | T1078 Valid Accounts                     |
| `reconnaissance`       | GET-only enumeration, no auth                              | T1046 Network Service Scanning           |
| `credential_attack`     | Credential reuse / spray (broader than brute force)        | T1110 Brute Force                         |
| `command_abuse`         | Interactive command execution in an SSH/Telnet session     | T1059 Command and Scripting Interpreter  |
| `command_injection`     | URI parameter injection attempting RCE                    | T1059                                    |
| `path_traversal`        | `../` / `%2e%2e` traversal attempts                       | T1005 Data from Local System             |
| `web_enumeration`       | Scanning web endpoints                                     | T1046                                    |
| `file_retrieval`        | Attempts to read sensitive files (passwd, shadow, .env)   | T1005                                    |
| `anomaly`               | Behavior does not match the training distribution         | (no automatic mapping)                   |
| `unknown`               | Behavior the platform could not classify                  | (no automatic mapping)                   |
| `benign`                | Non-attacker traffic (used as a negative class)            | n/a                                      |

## Important distinction: `unknown` vs `zero-day`

The platform deliberately distinguishes these:

- `unknown` — the platform's classifiers / anomaly detectors flagged the
  behavior, but could not confidently map it to a known class. This is a
  detection result.
- `zero-day` — a vulnerability exploitation technique that is genuinely
  unknown to defenders at the time of the attack. The platform **does not
  claim** to detect zero-days. An anomaly score is not proof of a zero-day.

The platform's documentation and dashboards use accurate language:
*behavioral anomaly detection*, *previously unseen pattern*, *unknown
attack-like behavior* — never *zero-day detection*.

## Stage taxonomy

The `attack.stage` field uses these values:

- `reconnaissance`
- `initial_access`
- `credential_access`
- `discovery`
- `execution`
- `persistence` (rare in this lab — honeypot doesn't allow it)
- `collection`
- `exfiltration`
- `command_and_control` (rare in this lab)
