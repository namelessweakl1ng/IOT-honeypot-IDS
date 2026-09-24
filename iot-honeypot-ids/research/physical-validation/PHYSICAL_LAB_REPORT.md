# Physical Lab Validation Report

## Date: 2026-09-25

## Environment

### Computer 2 (Fedora analysis server)
- Expected IP: 192.168.29.184
- Actual reachability from build environment: **UNREACHABLE** (timeout on all ports: 22, 9200, 5044, 5601, 8000)
- Docker: **NOT INSTALLED** in build environment
- Elasticsearch: **NOT RUNNING**
- Logstash: **NOT RUNNING**
- Kibana: **NOT RUNNING**
- FastAPI: **NOT RUNNING**

### Computer 1 (Raspberry Pi)
- Expected IP: 192.168.29.212
- Actual reachability from build environment: **UNREACHABLE** (timeout on all ports: 22, 2222, 8080, 9000)
- Docker: unknown (cannot reach)
- Honeypots: unknown (cannot reach)
- Filebeat: unknown (cannot reach)

### Computer 3 (Attacker)
- Not available as a dedicated machine
- Android/Termux: not tested

## Build Environment

The current execution environment is a cloud build environment (IP: 21.0.15.217, Debian 13 trixie).
It does NOT have:
- Docker installed
- SSH client installed
- Access to the lab network (192.168.29.0/24)

The lab machines (192.168.29.212 and 192.168.29.184) are on a private network
that is not reachable from this build environment.

## Step-by-Step Results

| Step | Description | Status | Evidence |
|---|---|---|---|
| 1 | Environment pre-flight | NOT RUN | Lab machines unreachable from build environment |
| 2 | Start Computer 2 (ELK stack) | NOT RUN | Docker not available; Fedora machine unreachable |
| 3 | Start Computer 1 (Pi honeypots) | NOT RUN | Pi machine unreachable |
| 4 | Filebeat validation | NOT RUN | Pi machine unreachable |
| 5 | Controlled benign event | NOT RUN | ELK stack not running |
| 6 | Event lineage verification | NOT RUN | No events generated |
| 7 | Controlled reconnaissance | NOT RUN | ELK stack not running |
| 8 | Controlled brute force | NOT RUN | ELK stack not running |
| 9 | Path traversal | NOT RUN | ELK stack not running |
| 10 | Command injection | NOT RUN | ELK stack not running |
| 11 | Ground-truth verification | NOT RUN | No campaigns executed |
| 12 | Hybrid lineage | NOT RUN | No detections produced |
| 13 | Dashboard validation | NOT RUN | Dashboard not accessible |
| 14 | Failure/recovery test | NOT RUN | ELK stack not running |
| 15 | Physical E2E script | NOT RUN | ELK stack not running |
| 16 | Resource measurement | NOT RUN | Pi unreachable |
| 17 | Latency measurement | NOT RUN | ELK stack not running |
| 18 | Evidence bundle | NOT RUN | No physical evidence collected |

## Software Test Baseline

| Command | Exit | Result |
|---|---|---|
| `python3 -m pytest tests/ --ignore=tests/integration --ignore=tests/e2e` | 0 | **869 passed** |

## Final Status

| Phase | Status | Evidence |
|---|---|---|
| Software tests | PASS | 869 passed, 0 failed |
| Pi deployment | NOT RUN | 192.168.29.212 unreachable from build environment |
| ELK deployment | NOT RUN | 192.168.29.184 unreachable; Docker not installed |
| Filebeat transport | NOT RUN | Pi unreachable |
| Telemetry ingestion | NOT RUN | ELK stack not running |
| Session reconstruction | NOT RUN | No telemetry ingested |
| Rules | NOT RUN | No sessions to evaluate |
| Classifier | NOT RUN | No sessions to evaluate |
| Anomaly detector | NOT RUN | No sessions to evaluate |
| Hybrid fusion | NOT RUN | No sessions to evaluate |
| Campaign correlation | NOT RUN | No sessions to correlate |
| Detection lineage | NOT RUN | No detections produced |
| Dashboard | NOT RUN | Dashboard not accessible |
| Failure recovery | NOT RUN | ELK stack not running |
| Resource measurement | NOT RUN | Pi unreachable |
| Latency measurement | NOT RUN | ELK stack not running |

## Required Next Actions

The physical lab validation CANNOT be performed from the current build environment.
The operator must execute these steps locally on the lab machines:

### On Computer 2 (Fedora, 192.168.29.184):
1. Ensure Docker is installed
2. Clone/copy the repository
3. Configure `dashboard/.env` with ELASTIC_PASSWORD + CENTRAL_SERVER_IP=192.168.29.184
4. Run: `cd iot-honeypot-ids && bash scripts/deployment/start-pc1.sh`
5. Verify: `curl -u elastic:<password> http://localhost:9200/_cluster/health`
6. Verify: `curl http://localhost:8000/health`

### On Computer 1 (Raspberry Pi, 192.168.29.212):
1. Ensure Docker is installed
2. Clone/copy the repository
3. Configure `pi/.env` with CENTRAL_SERVER_IP=192.168.29.184
4. Run: `cd iot-honeypot-ids/pi && docker compose --profile cowrie --profile camera --profile iot-service --profile default up -d`
5. Verify: `docker compose ps`

### On Computer 3 (attacker):
1. Use the Python attack simulator:
   ```bash
   cd iot-honeypot-ids/attacker
   pip install pyyaml
   cp config.example.yaml config.yaml  # set target.ip to 192.168.29.212
   python3 trapsig_attack.py validate --config config.yaml
   python3 trapsig_attack.py recon_basic --config config.yaml --dry-run
   python3 trapsig_attack.py recon_basic --config config.yaml --yes
   python3 trapsig_attack.py multi_stage --config config.yaml --seed 12345 --yes
   ```

### Run E2E from Computer 2:
```bash
cd iot-honeypot-ids
bash scripts/testing/run-e2e.sh --target 192.168.29.212 --scenario camera-recon
```
