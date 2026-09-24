# Camera HTTP honeypot

A lightweight Flask app that mimics a cheap IP camera / DVR.

## Endpoints

| Path         | Method | Purpose                                |
|--------------|--------|----------------------------------------|
| `/`          | GET    | Login form                            |
| `/health`    | GET    | Docker healthcheck                    |
| `/login`     | GET/POST | Login page / fake auth              |
| `/admin`     | GET    | Fake admin console                    |
| `/config`    | GET    | Network configuration                 |
| `/system`    | GET    | System info                           |
| `/status`    | GET    | CPU/mem/temp                          |
| `/network`   | GET    | Network info                          |
| `/users`     | GET    | User list                             |
| `/device`    | GET    | Device model                          |
| `/firmware`  | GET    | Firmware version                      |
| `/snapshot`  | GET    | Returns a 1x1 transparent PNG         |
| `/video`     | GET    | Stream unavailable                   |
| `/api/<...>` | GET    | Generic API catch-all                 |
| `/<path>`    | ANY    | Records any other probe              |

## Telemetry

Every request is appended as a JSON line to `/app/logs/camera.jsonl`
(inside the container). Filebeat tails this file and ships it to PC1.

Events follow the project's common event schema (see
[`shared/schemas/event-schema.json`](../../shared/schemas/event-schema.json)).

## Safety

- The container runs as a non-root user (`uid=10001`).
- The root filesystem is read-only; only `/tmp` and `/app/logs` are writable
  tmpfs mounts.
- No capabilities — `cap_drop: ALL`.
- No `/var/run/docker.sock` access.

See [`../../docker-compose.yml`](../../docker-compose.yml) for the runtime
configuration.
