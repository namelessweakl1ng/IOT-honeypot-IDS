# IoT service honeypot

A minimal TCP service that pretends to be a cheap IoT management daemon.

## Protocol

```
Server sends on connect:
  HELLO <device-id> IoT-MGMT-1.0\n

Client may send (newline-terminated):
  PING                       -> PONG\n
  STAT                       -> OK cpu=14 mem=96\n
  LIST                       -> OK devices=1\n
  AUTH <user> <pass>         -> AUTH-OK | AUTH-FAIL
  CMD <command>              -> EXEC-OK   (never actually executes anything)
  QUIT                       -> closes connection
  anything else              -> ERROR\n
```

## Telemetry

Every command and connection produces a JSON event in `/app/logs/iot.jsonl`.
Filebeat tails this file and ships it to PC1 Logstash.

## Safety

- Pure Python stdlib — no dependencies, tiny attack surface.
- Runs as non-root user (uid=10002).
- Read-only root filesystem, only `/tmp` and `/app/logs` are writable.
- `cap_drop: ALL` — no capabilities.
