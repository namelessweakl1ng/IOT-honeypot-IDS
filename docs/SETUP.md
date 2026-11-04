# Fedora/Linux laptop and Raspberry Pi deployment

Use an isolated private lab network you own. Never expose honeypot services or Elasticsearch to the public Internet. This guide describes a **split deployment**: the Raspberry Pi runs only sensor services; the Fedora laptop runs the analysis stack.

## 1. Lab topology and addresses

The verified physical-lab layout from one deployment was:

| Role | Host | Example address |
| --- | --- | --- |
| Analysis laptop | Fedora `deepwork` | `10.171.98.199` |
| Sensor | Raspberry Pi OS Lite, `berry` | `10.171.98.88` |
| Attacker | Kali in QEMU/libvirt | `192.168.122.151` |

Replace these example addresses with the addresses in your own lab. The Fedora and Pi addresses in this run shared `10.171.98.0/24`. Kali had Internet access through libvirt NAT and could connect to the Pi's forwarded honeypot ports without being on the same Wi-Fi.

**Important NAT caveat:** with this QEMU/libvirt NAT arrangement, the Pi and Filebeat observed Fedora's LAN address (`10.171.98.199`) as the source of Kali's connections, not Kali's guest address (`192.168.122.151`). The observed source address was confirmed in Elasticsearch event documents. Use the source address actually recorded by your sensor for experiment `attacker_ip`; do not assume the guest's private NAT address will be visible end-to-end. If you change the VM networking mode, re-check event `source.ip` before creating experiments.

## 2. Fedora analysis laptop

Clone the repository and configure the analysis environment:

```bash
git clone https://github.com/namelessweakl1ng/IOT-honeypot-IDS.git
cd IOT-honeypot-IDS
cp .env.example .env
$EDITOR .env
mkdir -p secrets
```

Set the environment values for the actual Pi and lab network. For the example deployment:

```dotenv
PI_HOST=10.171.98.88
PI_USER=trapsig
LAB_SUBNET=10.171.98.0/24
LOCAL_BIND_HOST=127.0.0.1
BEATS_BIND_HOST=0.0.0.0
```

Keep `LOCAL_BIND_HOST=127.0.0.1`. It controls the published host ports for Elasticsearch, Kibana, the frontend, the API, and Logstash monitoring. Do not change it to the libvirt address to make the API reachable: that would expose all those services on the VM network. `BEATS_BIND_HOST=0.0.0.0` publishes only the Beats input on port 5044 for the Pi.

### Optional API access from the Kali/libvirt network

The backend API is the only service that may need a separate libvirt-facing binding. Keep the normal Compose configuration loopback-only and use a one-off override that changes only the backend port:

```bash
cat > compose.api-libvirt.yml <<'YAML'
services:
  backend:
    ports:
      - "192.168.122.1:8000:8000"
YAML
docker compose -f docker-compose.yml -f compose.api-libvirt.yml up -d --no-deps --force-recreate backend
```

Replace `192.168.122.1` with Fedora's actual libvirt host-side address. Restrict access with the Fedora firewall to the libvirt subnet or the specific Kali guest. Do not use `LOCAL_BIND_HOST=0.0.0.0`. Return to the normal loopback-only binding by recreating the backend without the override:

```bash
docker compose up -d --no-deps --force-recreate backend
```

Check the API from Fedora at `http://127.0.0.1:8000`, and from Kali at the explicitly configured Fedora libvirt address only while the override is active.

### Backend SSH key and host-key setup

Create one dedicated key on Fedora. Do not overwrite or replace a key after installing its public half on the Pi. The private key is mounted into the backend container from the ignored `secrets/` directory:

```bash
ssh-keygen -t ed25519 -f secrets/pi_ssh_key -N '' -C trapsig-backend
chmod 600 secrets/pi_ssh_key
```

On the Pi, install the matching public key using the forced-command restriction below. The `PI_HOST` value is stored in `.env`, so load it before using it in shell commands:

```bash
set -a
. ./.env
set +a
: "${PI_HOST:?Set PI_HOST in .env first}"
ssh-keyscan -H "$PI_HOST" > secrets/known_hosts
ssh-keygen -lf secrets/known_hosts
chmod 600 secrets/known_hosts
```

Compare the ED25519 fingerprint printed by `ssh-keygen -lf secrets/known_hosts` with `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the Pi before trusting it. `ssh-keyscan` collects a key but does not authenticate the host by itself.

Run the laptop analysis services:

```bash
./scripts/preflight.sh
docker compose up -d --build
docker compose ps
```

Verify the stack:

```bash
curl -fsS http://127.0.0.1:9200/_cluster/health
curl -fsS http://127.0.0.1:5601/api/status
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:3000/
docker compose ps
```

## 3. Raspberry Pi sensor only

The Pi should run the services in `sensor/docker-compose.yml` only. Do **not** run the repository-root Compose stack on the Pi: Elasticsearch, Logstash, Kibana, FastAPI, and the Next.js frontend belong on the Fedora analysis laptop.

Install the repository at `/opt/trapsig`, then create the sensor's local environment file:

```bash
cd /opt/trapsig/sensor
cp .env.example .env
$EDITOR .env
```

For the example network:

```dotenv
SENSOR_ID=pi-01
ANALYSIS_HOST=10.171.98.199
LOGSTASH_PORT=5044
HONEYPOT_HOSTNAME=trapsig-pi
SENSOR_IP=10.171.98.88
```

Set `ANALYSIS_HOST` to Fedora's reachable lab-interface address and `SENSOR_IP` to the Pi's address. Protect the file:

```bash
chmod 600 .env
./scripts/setup.sh
./scripts/start.sh
./scripts/status.sh
docker compose ps
docker compose logs --tail=50 filebeat
docker compose exec filebeat filebeat test config -c /usr/share/filebeat/filebeat.yml --strict.perms=false
docker compose exec filebeat filebeat test output -c /usr/share/filebeat/filebeat.yml --strict.perms=false
```

A successful Filebeat output test should reach the configured Logstash host and port. In the verified deployment, Filebeat connected to `10.171.98.199:5044`. The sensor Compose project contained Cowrie, camera, router, IoT TCP, MQTT, Filebeat, and a one-shot custom-log initialization service. The initialization service may exit successfully; it is not a continuously running honeypot.

### Restricted backend management account

The backend uses a dedicated `trapsig` account to manage the sensor containers through a forced-command SSH wrapper. On the Pi, create the account and grant Docker access:

```bash
sudo useradd --create-home --shell /bin/bash trapsig
sudo usermod -aG docker trapsig
```

The new group membership applies only to a new login/SSH session. Reconnect before checking it. Verify that the account can access Docker:

```bash
id -nG trapsig
sudo -u trapsig docker info
```

The `docker` group is highly privileged and effectively root-equivalent. Use this dedicated account only for the backend management path. The wrapper runs the fixed script `/opt/trapsig/sensor/scripts/ssh-manage-wrapper.sh`; the project tree and scripts must be root-owned and not writable by `trapsig`.

Install the public key generated on Fedora (`secrets/pi_ssh_key.pub`) on the Pi. Create the SSH directory and add the key as a forced-command-only entry:

```bash
sudo install -d -o trapsig -g trapsig -m 700 /home/trapsig/.ssh
sudo sh -c 'printf "%s\\n" "command=\\"/opt/trapsig/sensor/scripts/ssh-manage-wrapper.sh\\",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty,no-user-rc $(cat /path/to/pi_ssh_key.pub)" > /home/trapsig/.ssh/authorized_keys'
sudo chown trapsig:trapsig /home/trapsig/.ssh/authorized_keys
sudo chmod 600 /home/trapsig/.ssh/authorized_keys
```

Replace `/path/to/pi_ssh_key.pub` with the actual path where you transferred the **public** key from Fedora. Never copy the private key to the Pi. Confirm the public key line starts with the `command=` restriction and has the `ssh-ed25519` key at its end. The wrapper permits only status and fixed `start|stop|restart` operations for `cowrie`, `camera`, `iot-service`, `mqtt`, and `router`. It must not be replaced with an unrestricted shell command.

From Fedora, install the same private key and known-hosts file at the paths used by Compose, then test the restricted command:

```bash
install -m 600 secrets/pi_ssh_key secrets/pi_ssh_key
ssh -i secrets/pi_ssh_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=secrets/known_hosts trapsig@"$PI_HOST" /opt/trapsig/sensor/scripts/manage.sh status
```

Do not commit `secrets/`, private keys, passwords, or real `.env` files.

## 4. Attacker VM connectivity

A Kali guest with libvirt's default NAT commonly has an address in `192.168.122.0/24` and a default gateway of `192.168.122.1`. That guest can initiate connections through Fedora to the Pi's lab address when routing/firewall policy allows it. A Wi-Fi adapter passed through to the VM or Wi-Fi bridging is not required for this outbound test path.

Check from Kali:

```bash
ip -4 -brief addr
ip -4 route
ping -c 3 10.171.98.88
```

Check only the fixed honeypot ports used by the project:

```bash
nc -vz -w 3 10.171.98.88 2222
nc -vz -w 3 10.171.98.88 2223
nc -vz -w 3 10.171.98.88 1883
nc -vz -w 3 10.171.98.88 8080
nc -vz -w 3 10.171.98.88 8081
nc -vz -w 3 10.171.98.88 9000
```

If connections fail, inspect the VM's libvirt network, host firewall, Pi firewall, and current DHCP addresses. Do not bridge a VM or change the Wi-Fi network blindly; first determine the route and source address actually seen by the Pi.

## 5. Resource and kernel checks on the Pi

The Pi should enforce the memory limits declared in its Compose file. Check the cgroup controllers and Docker warnings:

```bash
cat /sys/fs/cgroup/cgroup.controllers
docker info 2>/dev/null | grep -i 'No memory limit support'
```

The verified deployment initially had `cgroup_disable=memory` in `/proc/cmdline`; Docker consequently warned that memory and swap limits were unavailable. Do not treat that deployment as resource-limited until the kernel boot configuration and controller availability have been corrected and verified. Follow the Raspberry Pi OS documentation for the installed release before editing its one-line kernel command line. Do not blindly append a parameter that conflicts with an existing `cgroup_disable=memory` setting.

## 6. End-to-end smoke test

From the Pi, test Fedora's Logstash endpoint:

```bash
nc -vz 10.171.98.199 5044
docker compose exec filebeat filebeat test output -c /usr/share/filebeat/filebeat.yml --strict.perms=false
```

From Kali, run a bounded single-target connectivity check as above. Then use the controlled experiment workflow in [EXPERIMENTS.md](EXPERIMENTS.md) and the exact demonstration flow in [DEMO.md](DEMO.md).

## Troubleshooting observed deployment failures

- **Wrong IP/subnet:** check `ip -4 -brief addr` and `ip -4 route` on each host. A stale `192.168.98.x` value was once used where the actual network was `10.171.98.0/24`.
- **Fedora API not reachable at localhost from Kali:** keep the analysis services loopback-bound and use the optional backend-only Compose override above. Restrict the API port with Fedora's firewall.
- **Experiment rejects attacker/target IP:** `LAB_SUBNET` in Fedora's backend environment must contain both the attacker source address recorded by the Pi and the Pi target address. Recreate only the backend after editing Fedora's `.env`.
- **Ground-truth submission returns HTTP 409:** inspect the experiment with `GET /experiments/{id}`. Start it before running the scenario. The runner's timestamped summary must fall inside the experiment window, match the exact scenario manifest hash, target, and expected detection, and contain the scenario's complete ordered step list. The local run JSON is written before API submission.
- **SSH management reports unreachable:** verify `PI_HOST` is loaded from `.env`, compare the known-host fingerprint, verify the forced-command public key entry and file permissions on the Pi, and test the exact backend SSH command from Fedora.
- **Docker reports no memory limit support:** verify memory cgroup controller availability and inspect the kernel command line; do not claim resource limits are enforced until Docker no longer reports the warning.
- **Filebeat output test fails:** verify `ANALYSIS_HOST`, Logstash port 5044 publication, Fedora firewall, and Filebeat logs. A successful output test confirms transport to Logstash, not that every later analytics stage is correct.

Repository bind mounts use private SELinux `:Z` relabeling while remaining read-only. Cowrie image architecture should be checked from the registry manifest before pinning a digest; do not guess an ARM64 tag.

Physical resource enforcement and performance figures should be measured on the actual hardware. A single successful run is a deployment smoke test, not a general benchmark.
