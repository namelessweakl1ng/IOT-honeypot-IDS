# Deployment session findings and continuation handoff

> Last updated: 2026-11-04
>
> Purpose: preserve the concrete state and next actions from the Fedora / Raspberry Pi / Debian VM setup session so work can continue without repeating completed steps.

## Current state at a glance

- **Fedora analysis stack:** running and locally healthy.
- **Raspberry Pi honeypots:** five services reported running.
- **Fedora-to-Pi management SSH:** working with the dedicated key and strict host-key checking.
- **Debian attacker VM:** repository copied successfully; Internet access is unavailable, and the ICMP test to the Pi failed. TCP reachability to Pi services has not yet been tested.
- **Attack runner:** not yet executed; Paramiko is missing and pip could not reach the package index.
- **End-to-end telemetry:** not yet verified.

See [DEPLOYMENT_SESSION_EVALUATION.md](DEPLOYMENT_SESSION_EVALUATION.md) for the evidence table.

## Observed topology

~~~text
Fedora analysis laptop
  LAN: 192.168.29.184/24 (wlo1)
  - Docker Compose: Elasticsearch, Logstash, Kibana, FastAPI, Next.js
  - Logstash Beats input: host port 5044
  - Local web/admin ports: 3000, 8000, 9200, 5601, 9600
          |
          | same physical LAN
          |
Raspberry Pi sensor
  LAN: 192.168.29.212
  - Cowrie (SSH/Telnet)
  - camera persona
  - router persona
  - IoT TCP persona
  - MQTT persona
  - Filebeat (delivery to Fedora Logstash)

Fedora libvirt default NAT network
  bridge: virbr0
  Debian VM gateway: 192.168.122.1
          |
          |
Debian attacker VM
  Hostname: debian; architecture: x86_64
  IP: 192.168.122.213/24 (enp1s0)
  - repository at ~/IOT-honeypot-IDS
  - attacks/.venv created
~~~

The standard project architecture in [ARCHITECTURE.md](ARCHITECTURE.md) describes the analysis laptop and Pi. This session adds a third, separate Debian attacker VM.

## Fedora preflight and local worktree notes

The Fedora preflight completed with SELinux enforcing and the repository bind mounts using private `:Z` relabeling. Its output was:

~~~text
INFO: SELinux is Enforcing; repository bind mounts use private :Z relabeling.
TRAPSIG analysis preflight passed.
~~~

A later Fedora `git status` also showed `frontend/next-env.d.ts` as modified. It was not included in the Elasticsearch hostname commit. The session did not capture its diff or establish why it was modified. **Inspect the current worktree and file diff before staging or discarding it; do not automatically include or restore it.**

## Findings

### 1. Elasticsearch hostname issue is fixed

The analysis Compose file now contains:

~~~yaml
services:
  elasticsearch:
    hostname: elasticsearch
~~~

The change was committed directly to main in:

- Commit: ee48b0137c71306053271b602f7b332840ddf4b0
- Message: fix: set stable Elasticsearch container hostname

After the change, Elasticsearch became healthy and returned a green one-node cluster. The other core services also reported healthy. Do not remove the explicit hostname unless the original name-resolution failure is independently reproduced and a different fix is validated.

### 2. Fedora management SSH to the Pi works

The Fedora-side files were created:

- `~/.ssh/trapsig_pi` — generated Ed25519 private key kept on Fedora. A pre-existing key at this path was overwritten after the operator confirmed the replacement.
- `~/.ssh/trapsig_pi.pub` — matching public key.
- `secrets/pi_ssh_key` — private-key copy used by the laptop backend; file mode was set to `600`.
- `secrets/known_hosts` — Pi host keys collected with `ssh-keyscan -H`; file mode was set to `600`.

The session successfully ran the following from Fedora:

~~~bash
ssh -i secrets/pi_ssh_key -o UserKnownHostsFile=secrets/known_hosts -o StrictHostKeyChecking=yes trapsig@192.168.29.212 "/opt/trapsig/sensor/scripts/manage.sh status"
~~~

The returned status was:

~~~text
cowrie=running
camera=running
iot-service=running
mqtt=running
router=running
~~~

The Pi's ED25519 host-key fingerprint was compared with the ED25519 entry in Fedora's known_hosts output and matched. Do not copy secrets/, the private key, or other credentials to the Debian attacker VM. The tar transfer below intentionally excluded that directory.

**Address check:** the laptop .env was initially shown with PI_HOST=192.168.50.10, while the Pi later reported 192.168.29.212 from hostname -I. Confirm the current Fedora .env has PI_HOST=192.168.29.212 before restarting the backend or using Pi management.

### 3. Pi management account exists

On the Pi, `trapsig` already existed and its password was locked. It was added to the `docker` group; `id trapsig` showed that group, and `sudo -u trapsig docker info` returned Docker server details.

Docker-group membership is effectively root-equivalent. Keep the restricted SSH forced-command wrapper and do not grant the account general sudo or an unrestricted SSH key. Follow [SETUP.md](SETUP.md) for the intended account and wrapper permissions.

### 4. Debian VM repository copy succeeded

The first rsync attempt failed because the remote Debian side did not have the rsync command. The tar-over-SSH transfer then succeeded from Fedora:

~~~bash
cd ~/Downloads/IOT-honeypot-IDS/IOT-honeypot-IDS
tar --exclude='.git' --exclude='.venv' --exclude='secrets' -czf - . | ssh namelessweakling@192.168.122.213 'mkdir -p ~/IOT-honeypot-IDS && tar -xzf - -C ~/IOT-honeypot-IDS'
~~~

The Debian destination listing contained attacks, backend, docker-compose.yml, docs, elk, evaluation, frontend, scripts, sensor, and tests. The copy did not include Git history, the virtual environment, or secrets. Use Fedora as the source when refreshing this copy, or install rsync on both hosts before using rsync.

### 5. Debian VM networking is the current critical blocker

Debian reports:

~~~text
enp1s0: 192.168.122.213/24
default via 192.168.122.1
github.com resolves to 20.207.73.82
~~~

Observed tests:

- ping 8.8.8.8: 100% packet loss.
- ping 1.1.1.1: 100% packet loss.
- curl -I --connect-timeout 10 https://github.com: timeout.
- pip install -r requirements.txt: Network is unreachable.
- ping 192.168.29.212 from Debian: 100% packet loss (ICMP only; no TCP port probe was run from the VM).
- ping 192.168.29.212 from Fedora: 3/3 replies.

On Fedora, `virsh net-list --all` showed the default network active and persistent. `virsh net-info default` showed bridge `virbr0`; `virsh net-dumpxml default` showed `forward mode='nat'`. Firewalld showed `wlo1` in `FedoraWorkstation`, `virbr0` in `libvirt`, and Docker bridges in the `docker` zone.

This evidence points to a host-side forwarding, firewall, or NAT path that needs investigation, but **does not yet prove which component is responsible**. The following diagnostics have not yet been returned:

~~~bash
# Run on Fedora (the VM host)
sysctl net.ipv4.ip_forward
sudo firewall-cmd --zone=libvirt --list-all
sudo firewall-cmd --get-policies
sudo nft list ruleset | grep -E -C 5 'virbr0|192\.168\.122|masquerade'
ip route get 192.168.29.212
ip route get 8.8.8.8
~~~

Then, from Debian, collect:

~~~bash
ip route
ping -c 3 192.168.122.1
ping -c 3 192.168.29.212
curl -I --connect-timeout 10 https://github.com
~~~

Do not guess at firewalld/nftables changes or disable the firewall. Inspect the output first, then apply the smallest host-side rule that permits the intended lab traffic. virsh is a Fedora-host command; it is expected not to be installed inside Debian.

### 6. Attack runner setup is incomplete

Debian has python3, but no python command alias. A Python virtual environment was created at ~/IOT-honeypot-IDS/attacks/.venv.

The runner dependencies are pinned in attacks/requirements.txt:

~~~text
Paramiko==3.5.1
PyYAML==6.0.2
~~~

An invocation from inside `~/IOT-honeypot-IDS/attacks` failed with `ModuleNotFoundError: No module named 'attacks'` because the repository root was not the working directory. A later invocation from `~/IOT-honeypot-IDS` reached the runner import but failed with `ModuleNotFoundError: No module named 'paramiko'`. The attempt to install `attacks/requirements.txt` failed because the VM had no network access.

After network access is restored (or after transferring a compatible offline wheelhouse from Fedora), continue on Debian:

~~~bash
cd ~/IOT-honeypot-IDS
source attacks/.venv/bin/activate
python3 -m pip install -r attacks/requirements.txt
~~~

Create the attacker-side environment file and replace the example network values with the actual lab target:

~~~bash
cp attacks/.env.example attacks/.env
nano attacks/.env
~~~

For the addresses observed in this session, the target-side values are:

~~~dotenv
LAB_SUBNET=192.168.29.0/24
HONEYPOT_IP=192.168.29.212
~~~

Export the values and run from the repository root:

~~~bash
set -a
. attacks/.env
set +a
python3 -m attacks.runner.run multi-honeypot-attack --target "$HONEYPOT_IP"
~~~

The runner validates that the explicit target is a usable private IP inside LAB_SUBNET. It does not discover hosts or iterate CIDRs; its service ports and scenario actions are bounded as documented in [attacks/README.md](../attacks/README.md). Run scenarios only against the Pi honeypots in this authorized isolated lab. No scenario has been run yet.

### 7. Filebeat and end-to-end telemetry still need validation

The Pi status output came from manage.sh status, which checks the five honeypot containers. It did not establish Filebeat health or event delivery.

On the Pi, confirm the sensor environment uses the observed addresses:

~~~dotenv
SENSOR_ID=pi-01
ANALYSIS_HOST=192.168.29.184
LOGSTASH_PORT=5044
SENSOR_IP=192.168.29.212
~~~

These are values to verify/update in /opt/trapsig/sensor/.env; the session did not show that file's current contents. Then run on the Pi:

~~~bash
cd /opt/trapsig/sensor
docker compose ps
docker compose logs --tail=50 filebeat
docker compose exec filebeat filebeat test config -c /usr/share/filebeat/filebeat.yml --strict.perms=false
docker compose exec filebeat filebeat test output -c /usr/share/filebeat/filebeat.yml --strict.perms=false
~~~

The laptop Compose configuration binds Logstash Beats port 5044 to 0.0.0.0 by default, while the UI, API, Elasticsearch, Kibana, and Logstash monitoring ports are bound to 127.0.0.1 by default. Keep that exposure boundary unless there is a deliberate, documented reason to change it.

After a bounded scenario is run, verify that the corresponding event reaches Elasticsearch/Kibana and that the backend creates the expected session/detection. Preserve the runner's JSON ground-truth output under attacks/runs/. Because the API is loopback-bound by default, do not assume the Debian VM can post directly to the laptop API over the LAN; keep the local JSON artifact and transfer it back, or use an explicitly configured SSH tunnel if API submission is needed.

## GitHub CI validation for this handoff PR

GitHub Actions `TRAPSIG CI` run [#36](https://github.com/namelessweakl1ng/IOT-honeypot-IDS/actions/runs/41754900589) ran on PR #21 head `b58638c3ec6b861d5f55b0c51ea2bb8646f875cf` and completed successfully. The five successful jobs were Integration (Elasticsearch/Logstash/backend smoke checks), Contracts (Compose configuration, mount validation, sensor Compose configuration, shell checks), Python (dependency installation, Ruff, pytest), Docker Build (backend/frontend and sensor honeypot images), and Frontend (`npm ci`, lint, typecheck, production build). This validates the repository CI workflow only; it does not replace the outstanding physical Pi, Filebeat, Debian VM networking, attack-runner, or detection checks listed above.

## Recommended continuation order

1. On Fedora, verify PI_HOST and the lab subnet in .env.
2. Diagnose Fedora libvirt forwarding/firewall using the commands in Finding 5. Do not change firewall policy before inspecting the rules.
3. Restore and verify Debian-to-Pi reachability. Internet access is optional if dependencies are installed offline, but Pi reachability is mandatory.
4. Verify the Pi Filebeat output test can reach Fedora Logstash at port 5044.
5. Install Paramiko and PyYAML in the Debian attack virtual environment.
6. Run one bounded scenario against the explicit Pi target from the repository root.
7. Confirm telemetry ingestion and detection in the analysis stack.
8. Save the run JSON and only then proceed to the repeated attack/control matrix in [EVALUATION.md](EVALUATION.md).

## Explicitly not completed

- Debian-to-Pi routing or Internet access repair.
- Filebeat-to-Logstash output test and observed indexed event.
- Attack-runner dependency installation.
- Any attack scenario execution.
- Detection/ground-truth correlation.
- Formal repeated positive/control evaluation.
- Clock synchronization, resource sampling, restart idempotency, or Logstash interruption/recovery tests.
