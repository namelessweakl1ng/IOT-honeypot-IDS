# Attacker — Computer 2 (Fedora Linux)

Reproducible attack scenarios for the **user's own isolated lab honeypots**.

## Safety model — read first

1. Every scenario requires `--target <ip>`. There is no default.
2. The runner refuses any target that is not inside the configured
   `LAB_SUBNET` (set in `.env`).
3. The runner refuses obvious non-lab IPs (loopback, link-local, public DNS
   resolvers, RFC1918 multicast, etc.).
4. Scenarios are intentionally scoped — they target the specific ports the
   honeypots listen on. They do not perform broad network sweeps.
5. No persistence is established against any target. No credentials are
   exfiltrated to anywhere outside this repo. No command-and-control is
   deployed.

## Layout

| Folder              | Contents                                   |
|---------------------|--------------------------------------------|
| `scenarios/`        | YAML manifests: id, name, severity, steps  |
| `reconnaissance/`   | nmap / banner-grab scripts                 |
| `ssh/`              | SSH credential attacks (using sshpass)     |
| `http/`             | HTTP enumeration, path traversal, injection probes |
| `credentials/`      | Username/password lists (clearly synthetic) |
| `enumeration/`      | Service / endpoint enumeration             |
| `iot/`              | IoT service protocol probes                |
| `runner/`           | The `run-scenario.sh` wrapper + library    |

## Usage

```bash
cd attacker
cp .env.example .env                # set HONEYPOT_IP, LAB_SUBNET

./run-scenario.sh --target 192.168.1.50 --scenario ssh-bruteforce
./run-scenario.sh --target 192.168.1.50 --scenario camera-recon
./run-scenario.sh --target 192.168.1.50 --scenario multi-stage \
                  --campaign-id demo-001
```

Each run produces a `campaign_id` + `run_id` so experiments on PC1 are
reproducible. The runner writes a JSON summary to `./runs/`.

## Available scenarios

| ID                    | What it does                                       |
|-----------------------|----------------------------------------------------|
| `ssh-bruteforce`      | 30 SSH login attempts against the SSH honeypot     |
| `ssh-interaction`     | SSH login + command execution against Cowrie       |
| `camera-recon`        | GETs across all camera endpoints                   |
| `camera-default-creds`| POSTs default creds against `/login`               |
| `http-enumeration`    | Path traversal + command injection probes          |
| `iot-probe`           | Connects to the IoT service and probes commands    |
| `multi-stage`         | Recon → ssh → command exec → file retrieval        |
