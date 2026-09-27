# TRAPSIG IDS runtime and research platform

This directory contains the nested IDS backend/runtime, Raspberry Pi sensor deployment, attacker tooling, and research commands. The authoritative operator UI is the **repository-root** Next.js app in `../src/`; the authoritative IDS-domain API is this tree's FastAPI app at `dashboard/api/`. See [canonical architecture](docs/architecture/CANONICAL_ARCHITECTURE.md) and the single [college demonstration procedure](../DEMO.md).

## Machine roles

| Role | Responsibilities | Canonical code |
|---|---|---|
| Pi sensor | Cowrie, camera and IoT honeypots, collector, Filebeat | `pi/` |
| Analysis host | Elasticsearch, Logstash, Kibana, FastAPI, runtime session/detection logic | `dashboard/` |
| Attacker/test host | Bounded allow-listed scenarios; run summary contains scenario ground-truth metadata | `attacker/` |
| Browser UI | Root Next.js application and same-origin proxy routes | repository root `src/` |
| Offline research | IoT-23 preparation, validation, features, splits, models, artifacts | `model-lab/`, `research/`, `scripts/research/` |

## Data boundaries

- `PUBLIC_DATASET`: external IoT-23 network flows. Download/preparation and measured classifier experiments are separate offline work.
- `CONTROLLED_LAB`: planned controlled scenarios and actual physical Pi telemetry. Physical tests and resource/latency measurements are NOT RUN until performed on lab hosts.
- `LIVE_TELEMETRY`: current observations through FastAPI/Elasticsearch. LIVE is a runtime mode, not a ground-truth label.
- `SYNTHETIC`: test fixtures and explicit DEMO samples under `examples/demo/`. These are never research or physical evidence.

IoT-23 flows are not merged with Pi honeypot sessions. Dataset labels are analyst-derived external annotations; scenario metadata is ground truth only for the controlled run it describes; detector output remains prediction evidence.

## First-time setup

On the analysis host, from this directory:

```bash
./scripts/setup/init.sh
```

Replace every template secret/address in ignored `.env` files with locally configured values. Setup installs API/test dependencies and does not generate research data. Start the analysis stack with `./scripts/deployment/start-pc1.sh`; configure/start the Pi with `pi/scripts/configure.sh` and `pi/scripts/start.sh` after setting the Pi's analysis-host address. Use the preflight and complete command sequence in `../DEMO.md` before exposing services or running an attacker scenario.

The read-only lab preflight is:

```bash
./scripts/testing/preflight-lab.sh
```

It reports `PASS`, `FAIL`, or `SKIPPED`; it does not start or modify services.

## Public IoT-23 workflow

Download is explicit and raw data must remain outside this Git checkout:

```bash
export IOT23_DATA_DIR="$HOME/datasets/iot23"
./scripts/research/prepare-iot23.sh --download
PYTHONPATH=model-lab python -m model_lab.datasets.validate_iot23 research/datasets/iot23/prepared/normalized/flows.jsonl
```

See `research/datasets/iot23/README.md` for predownloaded archive/checksum handling, and the dataset card, feature mapping, and reproducibility document under `docs/research/`. The experiment runner fails when validation/provenance fails and never creates synthetic fallback data.

## Verification and status

Run the documented unit/integration checks with `scripts/testing/run-tests.sh`; use `scripts/testing/run-e2e.sh` only with configured API/Elasticsearch access, a unique lab secret, a reachable Pi, and LIVE mode. This repository includes historical experiment/model metadata and UI screenshots; they are not outputs from the final IoT-23 or physical campaigns.

Current results and explicit NOT RUN categories are in `docs/research/FINAL_VERIFICATION_REPORT.md` and `docs/research/FINAL_FREEZE_REPORT.md`. Do not claim a real dataset score, physical telemetry delivery, Raspberry Pi resource figure, latency, zero-day detection, or production readiness without the corresponding recorded experiment.
