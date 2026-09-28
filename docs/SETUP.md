# Fedora/Linux laptop and Raspberry Pi deployment

Use an isolated private lab network. The examples use `192.168.50.0/24`; replace them with your network. Never expose honeypots or Elasticsearch to the Internet.

## 1. Analysis laptop

```bash
git clone https://github.com/namelessweakl1ng/IOT-honeypot-IDS.git
cd IOT-honeypot-IDS
cp .env.example .env
$EDITOR .env                    # set PI_HOST and LAB_SUBNET
mkdir -p secrets
install -m 600 ~/.ssh/trapsig_pi secrets/pi_ssh_key
set -a; . ./.env; set +a
ssh-keyscan -H "$PI_HOST" > secrets/known_hosts
ssh-keygen -lf secrets/known_hosts
chmod 600 secrets/known_hosts
./scripts/preflight.sh
docker compose up -d --build
docker compose ps
```

Compare the displayed host-key fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` at the Pi console before trusting it. Never commit either key file. `LOCAL_BIND_HOST=127.0.0.1` keeps the UI, API, Kibana, Elasticsearch, and Logstash monitoring local. `BEATS_BIND_HOST=0.0.0.0` makes only Beats port 5044 reachable by the Pi; use a specific laptop lab-interface address if desired.

Verify the stack:

```bash
curl -fsS http://127.0.0.1:9200/_cluster/health
curl -fsS http://127.0.0.1:5601/api/status
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:3000/
docker compose exec frontend wget -q --spider http://127.0.0.1:3000/
docker compose ps
```

Repository bind mounts use private SELinux `:Z` relabeling while remaining read-only. Kibana has a 768 MiB Node heap and a 1536 MiB container limit because the lower physical-lab limit exhausted memory.

## 2. Raspberry Pi sensor

Copy or clone the repository so this directory is `/opt/trapsig/sensor`, then:

```bash
cd /opt/trapsig/sensor
cp .env.example .env
$EDITOR .env                    # set ANALYSIS_HOST, SENSOR_IP, SENSOR_ID
./scripts/setup.sh
```

Install the restricted management account and wrapper as an administrator:

```bash
sudo useradd --create-home --shell /bin/sh trapsig  # omit if it exists
sudo passwd --lock trapsig                         # key-only authentication
getent group docker                                # must exist from Docker installation
sudo usermod -aG docker trapsig
sudo chown -R root:root /opt/trapsig
sudo chmod 755 /opt /opt/trapsig /opt/trapsig/sensor /opt/trapsig/sensor/scripts
sudo chmod 644 /opt/trapsig/sensor/docker-compose.yml /opt/trapsig/sensor/.env
sudo chmod 755 /opt/trapsig/sensor/scripts/manage.sh /opt/trapsig/sensor/scripts/ssh-manage-wrapper.sh
sudo install -d -o trapsig -g trapsig -m 700 /home/trapsig/.ssh
```

The Docker installation must already have created the `docker` group. Start a **new login/SSH session** after `usermod`, then verify read/traverse access and Docker daemon access without granting sudo:

```bash
id trapsig                         # groups must include docker
namei -l /opt/trapsig/sensor/docker-compose.yml
sudo -u trapsig docker info
```

Membership in the Docker group is highly privileged (effectively root-equivalent). Do not grant the account general sudo or install an unrestricted key. This is why the backend key below is constrained to an exact forced-command whitelist. The root-owned project tree remains non-writable by `trapsig`; the explicit directory and file modes provide only the read/traverse access Compose needs.

Append the backend **public** key (never its private key) to `/home/trapsig/.ssh/authorized_keys` in this exact forced-command form:

```text
command="/opt/trapsig/sensor/scripts/ssh-manage-wrapper.sh",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc ssh-ed25519 AAAA... trapsig-backend
```

Then set ownership/mode and start:

```bash
sudo chown trapsig:trapsig /home/trapsig/.ssh/authorized_keys
sudo chmod 600 /home/trapsig/.ssh/authorized_keys
./scripts/start.sh
./scripts/status.sh
docker compose ps
docker compose logs --tail=50 filebeat
docker compose exec filebeat filebeat test config -c /usr/share/filebeat/filebeat.yml --strict.perms=false
docker compose exec filebeat filebeat test output -c /usr/share/filebeat/filebeat.yml --strict.perms=false
```

The one-shot `custom-logs-init` service idempotently assigns the named log volume to UID/GID 10001 before custom honeypots start. Honeypots remain read-only, capability-free, resource-limited, non-root containers. Their health probes and Cowrie's probe inspect listening sockets without creating attacker telemetry. Filebeat health tests configuration only, so a temporary Logstash outage does not cause restart churn.

The wrapper permits only the full commands requested by the backend: `/opt/trapsig/sensor/scripts/manage.sh status` and that fixed path followed by exact `start|stop|restart` operations for `cowrie`, `camera`, `iot-service`, `mqtt`, and `router`. Empty, shortened, interactive, forwarded, and arbitrary commands are rejected; `manage.sh` independently validates its arguments.

## Troubleshooting observed deployment failures

- **Fedora `AccessDeniedException` on ELK configuration:** use this Compose file's `:ro,Z` mounts; do not disable SELinux or make configs writable. Recreate containers after upgrading from an older checkout.
- **Kibana heap/OOM:** confirm `NODE_OPTIONS=--max-old-space-size=768` and the 1536 MiB limit in `docker compose config`.
- **Frontend unhealthy while host port works:** confirm `HOSTNAME=0.0.0.0`; the internal probe intentionally uses `127.0.0.1`, not `localhost`.
- **`PermissionError: /logs/*.jsonl`:** run `docker compose up custom-logs-init`, then start again. Never run honeypots as root.
- **Cowrie health reports missing `/bin/sh`:** recreate it with the exec-form Python healthcheck in this Compose file.
- **Filebeat health reports strict ownership:** confirm its health command includes `--strict.perms=false`, matching runtime.

Cowrie remains `cowrie/cowrie:latest`: this environment could not reach the upstream registry to verify an ARM64-compatible immutable digest. Do not replace it with an unverified guessed tag. Pin it only after inspecting the multi-platform manifest on a networked machine and testing on ARM64.

Physical Fedora SELinux behavior, Raspberry Pi ARM64 compatibility/resource enforcement, and end-to-end telemetry still require lab-hardware verification.
