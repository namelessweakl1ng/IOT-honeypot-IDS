# TRAPSIG complete rework brief

You are the lead engineer rebuilding TRAPSIG, an IoT honeypot and adaptive intrusion-detection research platform. Work in a dedicated feature branch. Inspect the repository before changing it, preserve working functionality, and do not fabricate successful tests or hardware measurements.

## Mission and operating model

Keep the data path:

controlled attacker -> Raspberry Pi honeypot services -> JSONL logs -> Filebeat -> Logstash -> Elasticsearch -> FastAPI processing -> Next.js SOC dashboard.

The attacker runs a bounded campaign against one explicitly configured honeypot IP. The Pi forwards telemetry to the analysis laptop. The backend correlates events into sessions, performs learned behavioural detection, chooses a defensive response, and publishes a complete explanation of the model decision and hardening action.

This is a private, explicitly authorized lab platform. Do not turn it into a general-purpose scanner or an offensive toolkit.

## Replace the signature/rule detector

Remove the hand-authored detection catalog completely. Do not leave the old threshold rules in parallel, hidden behind a feature flag, or as a silent fallback. Delete rule IDs, fixed brute-force/path-count/service-count thresholds, rule-specific detection types, stale evaluation labels, and UI text that calls detections "rules".

Use a learned behavioural model over normalized telemetry. Feature extraction should cover at least:
- protocol and service mix;
- event rate and timing;
- authentication outcomes and credential-attempt behaviour;
- HTTP path diversity and method patterns;
- SSH/Telnet interaction and command behaviour;
- IoT command sequences;
- MQTT packet operations, topic depth, and malformed traffic;
- cross-service fan-out and multi-stage session structure.

The detector must expose a numerical anomaly score, a calibrated decision boundary, model version, training/calibration sample count, event evidence IDs, and an explicit cold-start state. The model must learn from actual labelled control experiments and must not silently train on attack-labelled data as benign. Prevent repeated processor cycles from double-counting the same session or contaminating the baseline. Persist model state durably and version its feature schema.

A cold model must say that it is calibrating rather than pretending to have a trained detector. Provide a repeatable benign calibration scenario and document how many independent samples are required before interpreting performance.

## Reinforcement learning and adaptation

Use a contextual reinforcement-learning policy to choose among a small, audited set of reversible defensive profiles. The state must be derived from behavioural features and the anomaly score. The available actions should initially be:
- observe: record only;
- guarded: modest per-source throttling and short response delay;
- restrictive: stronger per-source throttling and bounded delay.

Use feedback from completed attack/control experiments to reward true positives and true negatives, penalize missed attacks and false positives, and penalize unnecessarily restrictive responses. Persist Q-values, policy version, action, state, reward, and update history. Make exploration configurable and conservative. Do not let the agent invent shell commands, firewall rules, ports, or arbitrary configuration.

The dashboard must show why an action was selected, the profile applied, its scope, expiry, and whether the Pi acknowledged it. Defensive actions must be reversible and time-bounded. A failed Pi-management connection must never be reported as a successful hardening action.

## Pi-side adaptation and containment

Implement an allowlisted policy control path from FastAPI to the Pi using the existing forced-command SSH account. Never grant a general remote shell. The Pi's custom camera, router, IoT TCP and MQTT personas should read a shared, read-only policy file at request time and apply profile-based per-source throttling/delay. Record a structured telemetry event when a request is throttled. Keep strict size/time limits and the existing container hardening.

Clearly disclose coverage limits: Cowrie is a separate upstream container and must not be represented as dynamically adapted unless that integration is actually implemented and tested. Do not block the analysis laptop, change host routing, change Wi-Fi settings, or apply unbounded firewall rules.

## Attack campaign engineering

Replace the predictable one-request demonstrations with richer protocol-aware, bounded campaigns against the one target selected by the operator:
- service-specific reconnaissance against the project's fixed honeypot ports;
- small, explicit fake-credential attempts against Cowrie and web login decoys;
- realistic but harmless SSH shell interactions inside Cowrie's fake filesystem;
- camera/router administration-page and endpoint enumeration;
- IoT command discovery and unauthorized command attempts against the fictional persona;
- MQTT connect, subscribe, publish, ping and disconnect sequences with harmless topic/payload values;
- multi-stage cross-service campaigns with realistic pauses and sequence variation;
- benign control traffic to train/calibrate the model.

Keep the current strict private-subnet and explicit-target guard. Never scan CIDR ranges, accept arbitrary URL/port overrides, target public addresses, exploit real devices, execute commands on the Pi host, deploy persistence, download payloads, create C2, exfiltrate data, or perform DoS. Bound attempts, payload size, concurrency, and duration. Emit local JSON ground truth with timestamps and a manifest hash, then submit it to the experiment API.

## Wi-Fi, router and mobile-hotspot setup

Make the laptop/Pi path resilient to DHCP address changes. Prefer local service discovery (mDNS/Avahi or an equivalent supported mechanism) for the analysis host's Logstash endpoint, with an explicit-IP fallback for networks that suppress multicast. Detect the Pi's outbound interface/source IP automatically. Verify TCP reachability to the analysis endpoint before starting Filebeat. Do not assume the Pi and laptop are on a fixed subnet or that a mobile hotspot permits client-to-client traffic; detect and explain blocked peer connectivity.

Keep the analysis stack on the laptop and the honeypot stack on the Pi. The laptop dashboard should expose a copyable/printable pairing status including resolved addresses and reachability without exposing SSH private keys or secrets. Provide one-command preflight/start/status flows and actionable failures. Never disable host firewalls or Wi-Fi isolation automatically.

## Dashboard and observability

The SOC dashboard should clearly separate:
- raw telemetry and event timeline;
- reconstructed attacker sessions;
- learned anomaly decisions and evidence;
- reinforcement-learning policy state/reward;
- defensive action history and Pi acknowledgement;
- model warm-up/calibration status;
- experiment ground truth and TP/FN/TN/FP/inconclusive outcomes.

Display the detected anomaly score, calibrated threshold, model version, selected profile, scope, expiry, action result, and related event IDs. Do not show a hardening action as applied merely because the policy recommended it.

## Engineering and validation

Keep FastAPI contracts typed and versioned. Preserve immutable raw events and stable/idempotent derived IDs. Add migrations or schema version changes for Elasticsearch indices where needed. Add unit tests for feature extraction, anomaly calibration, policy action selection, reward updates, policy expiry, Pi command allowlisting, malformed protocol handling, attack-target validation, and processor idempotence. Add end-to-end tests for baseline -> attack -> detection -> policy action -> dashboard visibility -> feedback update.

Update README, architecture, deployment, experiment and safety docs. Pin dependencies. Test backend, frontend lint/typecheck/build, Compose config, shell syntax, and CI. Report physical Pi performance as NOT MEASURED until hardware tests have actually been run.

## Acceptance criteria

1. No old rule detector or rule-specific detection labels remain in the active code path.
2. A new installation can pair Pi and laptop on a normal Wi-Fi LAN without hard-coding both DHCP addresses; fallback behavior is clear.
3. A benign calibration run trains the baseline and is not falsely labelled as an attack.
4. A varied multi-stage campaign yields a learned behavioural alert with event-level evidence.
5. The RL policy changes defensive profile based on feedback from completed experiments.
6. The custom honeypots acknowledge and enforce the selected profile; expired profiles revert automatically.
7. An unavailable Pi produces an honest failed/pending action state, never a false success.
8. Attack scripts remain single-target, private-lab-only, rate-bounded and non-destructive.
9. Unit/integration tests and documentation match the implemented behavior.
