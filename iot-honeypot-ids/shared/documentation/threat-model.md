# Threat model

## What this platform detects

The IoT honeypot IDS platform is designed to detect and classify **behavioral
patterns** observed against the lab honeypots:

- SSH credential attacks (brute force, default credentials, password spraying)
- HTTP reconnaissance (endpoint enumeration, path traversal, command injection)
- IoT service probing (banner grabs, malformed payloads, command abuse)
- Multi-stage intrusions (recon → credential attack → command exec → file retrieval)
- Previously-unseen behavioral anomalies (via Isolation Forest and similar)

## What it does NOT detect / claim

- **Zero-day vulnerabilities.** An anomaly detector cannot prove an event
  is a zero-day. The platform uses accurate language: *behavioral anomaly*,
  *previously unseen pattern*.
- **Attacks against the real Raspberry Pi host.** Honeypots run in Docker
  containers with capability drop + read-only filesystems. An attacker who
  escapes a honeypot container is *expected* to be contained.
- **Attacks against systems outside the lab.** The attacker tooling refuses
  targets outside the configured lab subnet.
- **Network-level attacks not visible at the application layer.** PCAP
  capture is optional and off by default.
- **Steganography, side-channels, or hardware attacks.** Out of scope.

## Trust boundaries

```
+----------------------------------------------------+
|  LAB LAN (192.168.1.0/24) — trust boundary 1      |
|                                                    |
|   PC2 (attacker) -----> Pi (honeypots)             |
|                            |                       |
|                            v                       |
|                         PC1 (ELK + ML + dashboard) |
+----------------------------------------------------+
                          |
                          v (telemetry forwarding only)
                  No outbound internet
```

The Pi only sends telemetry to PC1. PC1 only accepts Beats from the Pi and
API requests from the lab subnet. The attacker (PC2) is allowed to send
attack traffic to the honeypot ports on the Pi only — it cannot reach PC1's
ELK directly.

## Failure modes the platform tolerates

- PC1 unreachable → Pi keeps running honeypots; Filebeat spools locally
- Logstash down → Filebeat retries; no data lost
- Elasticsearch down → Logstash back-pressures; telemetry buffered
- ML service down → ELK + visualization still work
- One honeypot crashes → others stay up (Docker restart policy)
