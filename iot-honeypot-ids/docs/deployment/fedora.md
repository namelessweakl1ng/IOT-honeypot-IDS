# Fedora Linux setup (PC1 and/or PC2)

## PC1 (ELK + ML + API + Dashboard)

### 1. Install Docker Engine + Compose plugin

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable + start
sudo systemctl enable --now docker

# Add yourself to the docker group
sudo usermod -aG docker $USER
# re-login for group change to take effect
```

### 2. Install Python 3.11+ (for model-lab CLI)

Fedora ships Python 3.12+ by default — usually sufficient.

```bash
sudo dnf -y install python3 python3-pip python3-virtualenv
```

### 3. Clone + configure

```bash
git clone <your-repo> iot-honeypot-ids
cd iot-honeypot-ids
cp .env.example .env
# edit .env: set ELASTIC_PASSWORD, API_SECRET_KEY, etc.
cd dashboard
cp .env.example .env
# edit dashboard/.env: set the same passwords, model paths, etc.
```

### 4. Start ELK + API

```bash
cd dashboard
docker compose up -d
docker compose ps   # everything should be 'healthy' within ~90s
```

### 5. Verify

```bash
curl -u elastic:$ELASTIC_PASSWORD http://localhost:9200/_cluster/health
# expect: {"status":"green" or "yellow", ...}

curl http://localhost:8000/health
# expect: {"status":"ok","elasticsearch":"ok",...}

# Open Kibana in your browser:
xdg-open http://localhost:5601
```

### 6. Dashboard

The authoritative dashboard is the workspace-root Next.js application. Start it
from the workspace root with `bun run dev` after the FastAPI service is ready.

## Computer 3 (Attacker)

### 1. Install required tools

```bash
sudo dnf -y install bash python3 openssh-clients curl nmap-ncat sshpass
```

### 2. Clone + configure

```bash
git clone <your-repo> iot-honeypot-ids
cd iot-honeypot-ids/attacker
cp .env.example .env
# edit .env: set HONEYPOT_IP, LAB_SUBNET
```

### 3. Run a scenario

```bash
./run-scenario.sh --target 192.168.1.50 --scenario ssh-bruteforce
```

If the target is outside `LAB_SUBNET`, the runner refuses with exit code 4.

## Firewall

If you want a host firewall on PC1:

```bash
sudo systemctl enable --now firewalld
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.50/32 port port=5044 protocol=tcp accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.0/24 port port=5601 protocol=tcp accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.0/24 port port=8000 protocol=tcp accept'
sudo firewall-cmd --reload
```
