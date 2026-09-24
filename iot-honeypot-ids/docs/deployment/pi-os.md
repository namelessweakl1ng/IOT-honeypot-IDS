# Raspberry Pi OS Lite (64-bit) — Pi 4 setup

## 1. Flash the SD card

```bash
# On your laptop
# Option A: Raspberry Pi Imager (recommended)
#   - OS: Raspberry Pi OS Lite (64-bit)
#   - Storage: your SD card
#   - Advanced (gear icon): set hostname, SSH, user, password, WiFi

# Option B: rpi-imager CLI
rpi-imager write \
  --image ubuntu-22.04-preinstalled-server-arm64+raspi.img.xz \
  --device /dev/sdX
```

Enable SSH during imaging. Default user `pi` with a strong password.

## 2. First boot + SSH in

```bash
ssh pi@<PI_IP>
# Default password is what you set in the imager
```

## 3. Update + install Docker

```bash
sudo apt update && sudo apt -y upgrade
sudo apt install -y ca-certificates curl gnupy lsb-release
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add pi user to docker group (so you don't need sudo for docker)
sudo usermod -aG docker pi
# log out + back in for group change to take effect
```

## 4. Clone the repo

```bash
cd ~
git clone <your-repo> iot-honeypot-ids
cd iot-honeypot-ids/pi
cp .env.example .env
nano .env     # at minimum set CENTRAL_SERVER_IP
./scripts/configure.sh
```

## 5. Start the fleet

```bash
./scripts/start.sh
./scripts/status.sh
```

You should see all enabled honeypots + Filebeat in `running` state with low
CPU/RAM usage.

## 6. Verify telemetry reaches PC1

On PC1, check Logstash logs:

```bash
docker logs pc1-logstash --tail 50
# You should see 'Pipeline main started' and incoming Beats connections
```

On PC1 Kibana, go to **Discover** and select the `honeypot-events-*` index
pattern. You should see events within seconds of triggering them on PC2.

## Troubleshooting

| Symptom                                    | Fix                                                |
|--------------------------------------------|----------------------------------------------------|
| `cannot connect to the Docker daemon`      | `sudo systemctl start docker` + relogin            |
| Cowrie port 2222 already in use             | `ss -ltnp | grep :2222` — stop the conflicting svc  |
| Filebeat cannot reach PC1                   | Verify `CENTRAL_SERVER_IP` and firewall on PC1     |
| Pi runs out of disk                         | Reduce log rotation limits in compose, or ENABLE_PCAP=false |
| Pi becomes unresponsive under attack        | Lower `mem_limit` per container in compose          |
