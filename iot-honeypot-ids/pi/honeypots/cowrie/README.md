# Cowrie honeypot — supplementary docs

This directory holds the configuration that the `cowrie/cowrie:latest` Docker
image consumes.

- `cowrie.cfg` — main Cowrie configuration
- `userdb.txt` — credentials the honeypot accepts (everything else fails auth)
- `fs` — fake filesystem / `etc` content (a believable cheap IoT device)

The actual Cowrie runtime lives in the upstream Docker image. We only override
configuration files via bind mounts (see `docker-compose.yml`).

## Tuning

| Variable in `.env`        | Effect                                              |
|---------------------------|-----------------------------------------------------|
| `COWRIE_SSH_PORT`         | Host port mapped to Cowrie's container 2222         |
| `COWRIE_TELNET_PORT`      | Host port mapped to Cowrie's container 2223         |
| `COWRIE_MEM_LIMIT`        | Container memory cap (default 256M on Pi 4)         |
| `DEVICE_ID_COWRIE`        | Identifier that appears in the `device.id` field    |

## Logs

Cowrie writes structured JSON events to `/var/log/cowrie/cowrie.json` inside
the container. This is bind-mounted into a named volume `cowrie_var`, which
Filebeat tails and ships to PC1 Logstash.

To inspect locally:

```bash
docker exec pi-cowrie tail -f /var/log/cowrie/cowrie.json
```
