# TRAPSIG Attack Simulator

## What this is

A **safety-first, research-grade attack simulation harness** for controlled experiments against your own Raspberry Pi honeypot deployment.

It generates realistic, repeatable attacker behavior that produces telemetry flowing through:

```
Computer 2 (attacker)
  → Raspberry Pi honeypots (Cowrie / Camera / IoT-service)
  → Filebeat
  → Logstash
  → Elasticsearch
  → FastAPI
  → TRAPSIG detection pipeline
```

The simulator is **completely independent** of TRAPSIG's detection pipeline. It does NOT tell TRAPSIG what happened — TRAPSIG must infer behavior from telemetry. The simulator separately writes a local experiment manifest that acts as ground truth for later research analysis.

## What this is NOT

- **NOT** a general-purpose offensive security toolkit
- **NOT** an internet attack tool
- **NOT** an exploit framework
- **NOT** a password sprayer for arbitrary hosts
- **NOT** a vulnerability scanner

The simulator is **intentionally constrained** to the user's isolated IoT security lab. It refuses public IPs, arbitrary targets, and unbounded operations.

## Physical lab topology

```
┌─────────────┐       ┌──────────────┐       ┌─────────────┐
│  Computer 1 │       │  Raspberry   │       │  Computer 2 │
│  (PC1)      │       │  Pi 4        │       │  (attacker) │
│             │       │              │       │             │
│ Elasticsearch│←────│ Cowrie SSH   │←────│  This        │
│ Logstash    │     │ Camera HTTP   │     │  simulator   │
│ FastAPI     │     │ IoT TCP      │     │              │
│ TRAPSIG     │     │ Filebeat      │     │              │
│ Dashboard   │     │              │       │              │
└─────────────┘       └──────────────┘       └─────────────┘
```

## Installation

```bash
cd attacker/
pip install -r requirements.txt  # pyyaml only
cp config.example.yaml config.yaml
# Edit config.yaml — set target.ip to your Pi's IP
```

## Configuration

Edit `config.yaml`:

```yaml
target:
  ip: "192.168.1.50"     # Your Raspberry Pi IP

lab:
  allowed_cidrs:
    - "192.168.1.0/24"    # Your lab subnet

services:
  ssh:
    port: 2222            # Cowrie SSH port (matches Pi .env)
  camera:
    port: 8080            # Camera HTTP port
  iot:
    port: 9000            # IoT service TCP port

limits:
  max_connections: 30
  max_requests: 50
  max_auth_attempts: 10
  request_delay_ms: 250
  scenario_timeout_seconds: 120

safety:
  require_private_target: true
  require_explicit_target: true
  allow_localhost: false
```

## Safety model

The simulator enforces these constraints at the source — fail-closed:

1. **Target must be a valid IP** (no hostnames — DNS could bypass CIDR check)
2. **Target must be private** (when `require_private_target=true`)
3. **Target must be inside configured lab CIDR**
4. **Ports must be in the allowlisted set** (SSH, camera, IoT only)
5. **Scenarios must be in the allowlisted set** (6 predefined scenarios)
6. **All limits bounded with hard safety ceilings:**
   - max_connections ≤ 100
   - max_requests ≤ 200
   - max_auth_attempts ≤ 20
   - scenario_timeout ≤ 600s
7. **No arbitrary command execution** from CLI
8. **No subprocess with shell=True**
9. **No os.system calls**
10. **SIGINT/SIGTERM stops execution cleanly**

## Available scenarios

| Scenario | Behavior class | Description |
|---|---|---|
| `recon_basic` | reconnaissance | Bounded TCP probing of configured honeypot ports |
| `ssh_probe` | authentication_probing | Bounded SSH credential probing (8 synthetic creds) |
| `ssh_interaction` | command_execution | Cowrie shell session with safe recon commands |
| `web_recon` | web_enumeration | Bounded HTTP GET against camera endpoints |
| `iot_probe` | protocol_probing | Bounded IoT TCP protocol command probing |
| `multi_stage` | multi_stage_campaign | All 5 scenarios in sequence (campaign generator) |

## Timing profiles

| Profile | Delay behavior |
|---|---|
| `fast` | 1/4 of configured delay (min 50ms) |
| `normal` | Configured delay + small jitter (0-100ms) |
| `slow` | 2x configured delay + larger jitter (0-500ms) |

Use `--seed 12345` for reproducibility. The seed is recorded in the manifest.

## Usage

### List available scenarios

```bash
python3 trapsig_attack.py list
```

### Validate configuration

```bash
python3 trapsig_attack.py validate --config config.yaml
```

### Dry-run (no network traffic)

```bash
python3 trapsig_attack.py recon_basic --config config.yaml --dry-run
```

### Run a scenario

```bash
python3 trapsig_attack.py recon_basic --config config.yaml
python3 trapsig_attack.py multi_stage --config config.yaml --seed 12345 --profile normal --yes
```

## Pre-flight validation

Before every run (unless `--yes` or `--dry-run`):

```
TRAPSIG ATTACK SIMULATOR

TARGET:
  192.168.1.50

ALLOWED LAB:
  192.168.1.0/24

SCENARIO:
  multi_stage

MAX STAGES: 5
TIMEOUT: 120 seconds

This traffic is restricted to the configured TRAPSIG lab target.

Continue? [y/N]
```

## Run manifests

Every execution writes a JSON manifest to `sim/manifests/`:

```json
{
  "run_id": "RUN-20260912-a1b2c3",
  "scenario": "multi_stage",
  "started_at": "2026-09-12T12:00:00.000Z",
  "ended_at": "2026-09-12T12:02:30.000Z",
  "target": { "ip": "192.168.1.50", "services": {...} },
  "attacker": { "hostname": "fedora-pc2", "platform": "Linux-6.x..." },
  "profile": "normal",
  "seed": 12345,
  "stages": [...],
  "statistics": { "connections": 12, "requests": 30, "auth_attempts": 8 },
  "status": "completed"
}
```

**No secrets are ever written to manifests.** Credentials are identified by profile index only (`credential_profile_3`), never plaintext.

## Known / held-out scenario methodology

For research evaluation, scenarios are split:

- **KNOWN** (used in training): `recon_basic`, `ssh_probe`, `web_recon`
- **HELD-OUT** (unknown-family evaluation): `multi_stage`

This split is **explicit and documented** — not random. The simulator itself does NOT train the model; it only generates telemetry + ground-truth manifests for later comparison.

## Complete example experiment

```bash
# STEP 1: Configure Pi target
cd attacker/
cp config.example.yaml config.yaml
# Edit config.yaml — set target.ip to your Pi's IP

# STEP 2: Validate
python3 trapsig_attack.py validate --config config.yaml

# STEP 3: Dry-run recon
python3 trapsig_attack.py recon_basic --config config.yaml --dry-run

# STEP 4: Run recon
python3 trapsig_attack.py recon_basic --config config.yaml --yes

# STEP 5: Wait for TRAPSIG telemetry (check dashboard)

# STEP 6: Run multi-stage campaign
python3 trapsig_attack.py multi_stage --config config.yaml --seed 12345 --yes

# STEP 7: Observe in TRAPSIG dashboard:
#   events → sessions → campaign → features → detections

# STEP 8: Compare the generated manifest (sim/manifests/) with
#         TRAPSIG observations (dashboard / API)
```

## Stopping execution

Press `Ctrl+C` at any time. The simulator:
- Immediately stops starting new requests
- Closes open connections where possible
- Writes a manifest with `status: "interrupted"`

## Expected TRAPSIG telemetry flow

```
Attack simulator generates traffic
    ↓
Pi honeypots receive traffic + write JSON logs
    ↓
Filebeat ships logs to Logstash
    ↓
Logstash normalizes + indexes in Elasticsearch
    ↓
FastAPI session materializer creates sessions (15s scheduler)
    ↓
Campaign correlator groups sessions by source IP + temporal proximity
    ↓
Feature extractor computes v2 feature vectors
    ↓
Hybrid detector evaluates: rules + anomaly (if trained) + supervised (if active)
    ↓
Detection persisted if a signal exists
    ↓
Dashboard displays: event → session → campaign → features → detection → lineage
```

## Research reproducibility

- Use `--seed 12345` for deterministic run ordering
- The seed is recorded in the manifest
- Same seed + same config → same planned sequence
- Compare manifests across runs to verify reproducibility

## Troubleshooting

| Problem | Solution |
|---|---|
| `REFUSED: target ... is outside the configured CIDR` | Edit `config.yaml` — add your subnet to `lab.allowed_cidrs` |
| `REFUSED: target ... is a public IP` | Use a private IP (192.168.x.x, 10.x.x.x) |
| `REFUSED: port ... is not in the allowed ports` | Only SSH (2222), camera (8080), IoT (9000) ports are allowed |
| `ModuleNotFoundError: No module named 'sim'` | Run from the `attacker/` directory, or use `python3 trapsig_attack.py` |
| Connection refused | Pi honeypots not running — start them on the Pi first |

## Dependencies

- Python 3.10+
- PyYAML (for config parsing)
- No root privileges required
- No Docker required on Computer 2
