# Deployment session evaluation

> Scope: one operator-led deployment and troubleshooting session covering a Fedora analysis laptop, a Raspberry Pi sensor, and a Debian attacker VM.
>
> Status: **analysis stack operational; Pi management reachable from Fedora; attacker VM Internet access and attack execution blocked.**
>
> Evidence source: terminal output supplied during the session plus inspection of repository configuration. This is a deployment smoke evaluation, not a formal detection-performance study.

## Executive summary

The Fedora analysis stack was brought to a healthy state after adding an explicit Elasticsearch container hostname. The change was committed to **main** as **ee48b0137c71306053271b602f7b332840ddf4b0** with message **fix: set stable Elasticsearch container hostname**.

From Fedora, SSH access to the Pi succeeded using the dedicated management key and strict known-host checking. The Pi management status command reported all five honeypot services as running.

The Debian attacker VM received a copy of the repository over SSH using a tar stream. However, it has no usable outbound Internet access, and its ICMP ping test to the Pi failed. DNS lookup for GitHub succeeds, but outbound connectivity tests time out. TCP reachability to Pi service ports has not yet been tested. Its attack-runner dependencies are therefore not installed, and no attack scenario has been executed.

**Conclusion:** the analysis services are locally available, and Pi management from Fedora is verified. The complete attacker-to-honeypot-to-Filebeat-to-Logstash-to-Elasticsearch path remains unverified.

## Observed lab topology

| Role | Observed address / interface | Evidence |
|---|---|---|
| Fedora analysis laptop | 192.168.29.184/24, Wi-Fi interface wlo1 | Fedora ip address output |
| Raspberry Pi sensor | 192.168.29.212 | Pi hostname -I; Fedora ping succeeded |
| Debian attacker VM | 192.168.122.213/24, interface enp1s0 | Debian ip addr |
| Debian VM default gateway | 192.168.122.1 | Debian ip route |
| Fedora libvirt network | default, active NAT, bridge virbr0 | virsh net-list, net-info, net-dumpxml |

These are private lab addresses observed during this session. Re-check them before reusing this note after network changes.

## Verification results

| Area | Result | Evidence and interpretation |
|---|---|---|
| Fedora preflight | **PASS** | ./scripts/preflight.sh printed TRAPSIG analysis preflight passed. |
| Docker image build | **PASS** | Compose built the backend and frontend images successfully before the initial Elasticsearch startup failure. |
| Elasticsearch startup | **PASS after local fix** | Adding hostname: elasticsearch to the Elasticsearch service resolved the startup/name-resolution issue observed in the session. The change is present on main in commit ee48b01. |
| Elasticsearch health | **PASS** | /_cluster/health returned status green, one node, 45 active primary shards, and 45 active shards. |
| Backend health | **PASS** | /health returned a healthy response with Elasticsearch reported as green. |
| Frontend | **PASS** | curl -I http://127.0.0.1:3000/ returned HTTP/1.1 200 OK. |
| Logstash and Kibana | **PASS** | Both were reported healthy in docker compose ps. |
| Compose service state | **PASS** | Elasticsearch, Logstash, Kibana, backend, and frontend were all reported Up and healthy. |
| Fedora-to-Pi network | **PASS** | Fedora pinged 192.168.29.212 successfully (3 packets received). |
| Fedora-to-Pi SSH management | **PASS** | SSH using secrets/pi_ssh_key, secrets/known_hosts, and StrictHostKeyChecking=yes successfully ran the Pi management status command. |
| Pi honeypot process state | **PASS, running state only** | The status script reported cowrie, camera, iot-service, mqtt, and router as running. This does not establish end-to-end telemetry delivery. |
| Pi management account | **PASS** | On the Pi, trapsig was present in the docker group and sudo -u trapsig docker info returned Docker server information. Docker-group membership is highly privileged; retain the repository's restricted-command/SSH-wrapper controls. |
| Repository transfer to Debian | **PASS** | A tar archive stream over SSH copied the repository tree to ~/IOT-honeypot-IDS; the destination listing showed the expected project directories. .git, .venv, and secrets were excluded. |
| Debian Internet access | **BLOCKED** | Pings to 8.8.8.8 and 1.1.1.1 received no replies; GitHub DNS resolved to 20.207.73.82, but HTTPS to GitHub timed out and pip reported Network is unreachable. |
| Debian-to-Pi ICMP test | **FAILED; TCP UNTESTED** | Ping from Debian to 192.168.29.212 received no replies. No TCP port probe was run from the VM. Fedora-to-Pi ping succeeded. |
| Debian attack dependencies | **BLOCKED** | Python 3 is present and a virtual environment was created, but importing the runner failed because paramiko is absent. Installing attacks/requirements.txt could not reach the package index. |
| Attack runner invocation | **NOT COMPLETED** | One invocation was attempted from inside attacks/, where attacks.runner.run is not importable as a top-level module. The correct working directory is the repository root. |
| Filebeat-to-Logstash delivery | **NOT VERIFIED** | No Filebeat output test, Logstash ingress confirmation, or indexed sensor event was provided. |
| Attack detection and experiment metrics | **NOT MEASURED** | No scenario was executed, so there are no ground-truth records, detections, precision/recall values, or latency measurements from this session. |
| Physical resource/recovery evaluation | **NOT MEASURED** | No CPU/RAM sampling, restart-idempotency test, Logstash interruption/recovery test, or clock-synchronization evidence was collected. |

## Key interpretation

1. The Elasticsearch hostname change is a confirmed local deployment fix and is already on main.
2. The analysis stack's local health checks passed. This proves service startup and local HTTP health, not that sensor events are arriving.
3. Pi management is reachable from Fedora. The reported five honeypot services were running when checked.
4. The Debian VM is attached to the Fedora libvirt NAT network. Its outbound Internet tests failed, and its ICMP ping test to the Pi failed; TCP reachability to Pi services has not been tested. The exact host-side forwarding/firewall cause has **not** been established; net.ipv4.ip_forward, firewalld policy output, and the relevant nftables rules were requested but not supplied.
5. The attack runner has not yet generated traffic. Missing Python dependencies and missing network reachability are independent blockers.

## Evaluation boundary

This document records deployment smoke checks only. It does not replace [EVALUATION.md](EVALUATION.md), which defines the formal repeated-scenario methodology, positive/control cohorts, confusion-matrix rules, latency/resource measurements, and recovery tests.

Until the remaining steps in [DEPLOYMENT_SESSION_FINDINGS.md](DEPLOYMENT_SESSION_FINDINGS.md) are completed, do not claim that the complete telemetry pipeline or attack-detection evaluation has passed.
