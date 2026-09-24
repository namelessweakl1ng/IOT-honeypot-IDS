# TRAPSIG — IoT Honeypot + ELK + Machine-Learning IDS Research Platform

A controlled cybersecurity laboratory for final-year research / demonstration.
It captures real attacker telemetry from a Raspberry Pi-based honeypot fleet,
normalizes it through an ELK stack, reconstructs attack sessions, extracts
behavioral features, trains interpretable ML baselines, and detects both
**known** and **previously unseen** anomalous behavior.

> This is a defensive research platform. All attacker tooling targets **only**
> the user's isolated lab honeypots. It refuses arbitrary internet targets.

---

## 1. What This Project Is

A software-defined research pipeline with an explicitly unverified physical deployment:

```
Computer 3: Attacker
   |
   | controlled attack
   v
Raspberry Pi 4 Honeypot Fleet (Cowrie SSH, Camera HTTP, IoT service)
   |
   | structured JSON telemetry
   v
Computer 2: Fedora analysis host
   |
   +--> Filebeat / Logstash ingestion
   +--> Elasticsearch indexing
   +--> Kibana visualization
   +--> session reconstruction
   +--> feature extraction
   +--> rule engine (known patterns)
   +--> ML engine (classifier + anomaly)
   +--> dataset versioning
   +--> model training / evaluation / registry
   v
Replay an attack -> telemetry is correlated -> the configured detector evaluates it.
Physical delivery and latency remain unverified until the lab is run.
```

The system never fakes results. When a feature is incomplete, it is labeled as
such (e.g. `INSUFFICIENT DATA`), never silently fabricated.

---

## 2. Hardware / Network Topology

```
                 ROUTER (ordinary LAN)
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
       Pi 4        PC1         PC2
   Honeypot fleet  ELK + ML   Attacker
   (4 GB RAM)      analysis   scenarios
```

| Machine  | OS                         | Role                                            |
|----------|----------------------------|-------------------------------------------------|
| Computer 1 | Raspberry Pi OS Lite 64-bit | Deception + telemetry + forwarding           |
| Computer 2 | Fedora Linux                | ELK + ML + FastAPI + Next.js dashboard        |
| Computer 3 | Configured lab host         | Reproducible attacker scenarios                |

See [`docs/architecture/network.md`](docs/architecture/network.md) for required
ports and [`docs/deployment/`](docs/deployment/) for per-OS setup.

---

## 3. Repository Layout

```
iot-honeypot-ids/
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── pi/                # Raspberry Pi: honeypots, collector, filebeat, scripts
├── dashboard/         # Computer 2: ELK + FastAPI + runtime ML
├── attacker/          # Computer 3: reproducible attack scenarios
├── model-lab/         # Computer 2: ML research workspace
├── shared/            # ECS-style schema, attack-type taxonomy, docs
├── docs/              # architecture / deployment / security / ml / demo
├── scripts/           # setup / dev / deployment / testing / demo entry points
└── tests/             # unit + integration + e2e
```

The runtime and research tooling live in this nested project directory. The
workspace root contains the authoritative Next.js dashboard shell; it is the
only production UI. Physical deployment remains a separate verification step.

---

## 4. Quick Start

### 4.1 Computer 1 (ELK + ML + API + Dashboard)

```bash
git clone <repo> iot-honeypot-ids
cd iot-honeypot-ids
cp .env.example .env                 # edit CENTRAL_SERVER_IP, passwords, etc.
cd dashboard
cp .env.example .env
docker compose up -d                 # Elasticsearch + Logstash + Kibana + API
```

Kibana: `http://<PC1_IP>:5601`
API:    `http://<PC1_IP>:8000/health`

### 4.2 Raspberry Pi 4 (Honeypot)

```bash
ssh user@PI_IP
cd ~/iot-honeypot-ids/pi
cp .env.example .env                 # set CENTRAL_SERVER_IP, HONEYPOT_PORTS, etc.
./scripts/start.sh                   # starts Cowrie + Camera + IoT + Filebeat
./scripts/status.sh                  # resource usage + health per container
```

### 4.3 Computer 2 (Attacker)

```bash
cd ~/iot-honeypot-ids/attacker
cp .env.example .env                 # set HONEYPOT_IP / LAB_SUBNET
./run-scenario.sh --target 192.168.1.X --scenario ssh-bruteforce
```

The runner refuses any target outside the configured lab subnet.

### 4.4 Full demo (PC1 orchestrator)

```bash
./scripts/demo/run-demo.sh --target 192.168.1.X
```

This walks through system check -> honeypot check -> ELK check -> attack ->
telemetry -> session reconstruction -> ML detection -> unknown pattern ->
label -> retrain -> evaluate -> replay -> final detection.

---

## 5. What Runs Where

| Concern                          | Pi 4            | PC1            | PC2         |
|----------------------------------|-----------------|----------------|-------------|
| Cowrie SSH/Telnet honeypot       | yes             |                |             |
| Camera HTTP honeypot              | yes             |                |             |
| IoT service honeypot              | yes             |                |             |
| Filebeat / telemetry forwarding  | yes             |                |             |
| Elasticsearch                     |                 | yes            |             |
| Logstash                         |                 | yes            |             |
| Kibana                           |                 | yes            |             |
| FastAPI (sessions/detections)    |                 | yes            |             |
| React custom dashboard           |                 | yes            |             |
| Feature extraction / training    |                 | yes            |             |
| Model registry / experiments     |                 | yes            |             |
| Attack scenarios                  |                 |                | yes         |

The Pi never runs Elasticsearch, Kibana, model training, or large Python ML
workloads.

---

## 6. Configuration

All runtime knobs live in `.env` files (one per machine). See:

- [`.env.example`](.env.example) (root, project-wide)
- [`pi/.env.example`](pi/.env.example)
- [`dashboard/.env.example`](dashboard/.env.example)
- [`attacker/.env.example`](attacker/.env.example)

Key variables: `PI_IP`, `CENTRAL_SERVER_IP`, `LOGSTASH_PORT`,
`ELASTICSEARCH_PORT`, `KIBANA_PORT`, `HONEYPOT_PORTS`, `ENABLE_PCAP`,
`ENABLE_COWRIE`, `ENABLE_CAMERA`, `ENABLE_IOT_SERVICE`, `MODEL_PATH`,
`DATA_PATH`.

Secrets are never committed. `.gitignore` blocks `.env`, captured PCAPs,
trained model artifacts, and SSH keys.

---

## 7. ML Architecture (Hybrid)

```
                    EVENT / SESSION
                         |
              +----------+----------+
              |                     |
         Rule Engine            ML Engine
         (deterministic)         |
                          +------+------+
                          |             |
                     classifier    anomaly detector
                     (Random Forest,   (Isolation Forest,
                      LogReg, GB)       One-Class SVM)
```

- Rules handle obvious deterministic patterns.
- Classifier handles known attack classes.
- Anomaly detector flags previously-unseen behavior.

See [`docs/ml/architecture.md`](docs/ml/architecture.md) and
[`model-lab/README.md`](model-lab/README.md).

---

## 8. Reproducibility

Every experiment records:

```
dataset version, feature version, model algorithm, hyperparameters,
training timestamp, random seed, metrics, model version
```

Models are never overwritten. The registry tracks statuses:
`experimental -> validated -> active -> retired`.

See [`docs/ml/reproducibility.md`](docs/ml/reproducibility.md).

---

## 9. Testing

```bash
# unit (parsers, normalizers, feature extraction, session reconstruction)
pytest tests/unit -v

# integration (honeypot -> logs -> logstash -> es -> api -> ml)
pytest tests/integration -v

# end-to-end (attack scenario -> telemetry -> session -> detection)
./scripts/testing/run-e2e.sh --target 192.168.1.X
```

---

## 10. Safety / Ethics

- All attacker scripts require an explicit `--target` and refuse obvious
  non-lab IPs.
- Honeypots run inside Docker with capability drop, read-only filesystems
  where practical, resource limits, and isolated networks.
- `/var/run/docker.sock` is never exposed to attacker-facing containers.
- The Pi host shell is never reachable from a honeypot.
- This project distinguishes `unknown` from `zero-day`. An anomaly detector
  cannot automatically prove an event is a zero-day vulnerability.

See [`docs/security/safety.md`](docs/security/safety.md).

---

## 11. License

MIT — see [`LICENSE`](LICENSE).

---

## 12. Status

This is a working final-year project skeleton that contains:

- Real honeypot Docker Compose for the Pi (Cowrie + Camera + IoT service)
- Real ELK Compose for PC1 with pinned versions and ECS-style Logstash pipelines
- Real FastAPI service exposing sessions / detections / models / experiments
- Real ML pipeline (feature extraction, train, evaluate, replay, compare)
- Real attacker scenarios with safety checks
- Real replay / demo orchestrator
- Tests for parsers, normalizers, features, sessions, serialization, config
- Offline development mode using clearly-labeled synthetic sample data

Anything still marked `TODO` or `INSUFFICIENT DATA` is the genuine state of
that subsystem — no fake metrics are produced to hide gaps.
