# Architecture

## High-level diagram

```
                 ROUTER (ordinary LAN)
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
       Pi 4        PC1         PC2
   Honeypot fleet  ELK + ML   Attacker
   (4 GB RAM)      analysis   scenarios
```

## Component diagram

```
+--------------------------------------------------+
|  Raspberry Pi 4                                  |
|                                                  |
|   Cowrie (SSH/Telnet) ─┐                         |
|   Camera (HTTP)        ├──> JSONL logs           |
|   IoT service (TCP)    ┘         |               |
|                                  v               |
|                             Filebeat            |
|                                  |               |
+----------------------------------|---------------+
                                   | Beats (TCP 5044)
                                   v
+--------------------------------------------------+
|  Computer 1                                      |
|                                                  |
|   Logstash ──> Elasticsearch ──> Kibana          |
|                  |                               |
|                  v                               |
|               FastAPI ────> React dashboard      |
|                  |                               |
|                  v                               |
|             model-lab CLI                       |
|             (train / evaluate / replay)         |
+--------------------------------------------------+
        ^                            ^
        |                            |
   telemetry only             attacker scenarios
   (no inbound)               (only honeypot ports)
```

## Trust boundaries

| Boundary | Direction | Allowed traffic                                  |
|----------|-----------|--------------------------------------------------|
| Pi → PC1 | outbound  | Filebeat Beats over TCP 5044                      |
| PC2 → Pi | inbound   | SSH/Telnet/HTTP/TCP to honeypot ports only       |
| PC1 → Pi | outbound  | SSH (admin) only                                 |
| LAN → PC1| inbound   | Kibana (5601), API (8000) — restricted to lab subnet |

See [`security/safety.md`](security/safety.md) for the full hardening checklist.

## Sub-pages

- [`network.md`](network.md) — physical topology + required ports
- [`data-flow.md`](data-flow.md) — end-to-end telemetry path
- [`components.md`](components.md) — per-container inventory
