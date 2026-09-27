# Reproducibility procedure

This procedure has not yet been executed from a fresh machine. Exact dependency versions are read from tracked configuration where pinned; runtime tool versions and physical host information must be captured during the actual run.

## Tracked version sources

| Component | Repository configuration | Version status |
|---|---|---|
| API/runtime Python | `dashboard/api/Dockerfile`, `dashboard/api/requirements.txt` | Container base `python:3.11-slim-bookworm`; API Python packages pinned in requirements |
| Research Python | `requirements.txt` and `dashboard/api/requirements.txt` | Shared requirements pin pytest, lint, and API/ML packages; run `python3 --version` and record actual version |
| Root UI | `package.json`, `bun.lock` | Package ranges plus Bun lock; no Bun runtime pin; record `bun --version` |
| Elasticsearch | `dashboard/docker-compose.yml` | `${ELK_VERSION:-8.13.4}` |
| Logstash | `dashboard/docker-compose.yml` | Same ELK_VERSION as Elasticsearch |
| Kibana | `dashboard/docker-compose.yml` | Same ELK_VERSION as Elasticsearch |
| Filebeat | `pi/docker-compose.yml` | `${ELK_VERSION:-8.13.4}` |
| Cowrie | `pi/docker-compose.yml` | `cowrie/cowrie:latest` (mutable tag; record pulled image digest) |
| Local Pi honeypot images | Pi Dockerfiles and compose | Built locally; record image IDs/digests |
| Docker/Compose | Host installation | Not pinned by repository; record `docker version` and `docker compose version` |
| OS/hardware | physical hosts | Not pinned; record distribution release, kernel, CPU model, Pi model/RAM, storage, topology, and clock-sync status |

## Clean setup

1. Clone the frozen Git commit and record `git rev-parse HEAD` and `git status --short`.
2. Install the documented Bun runtime and run `bun install --frozen-lockfile`; record `bun --version` and Node version if present.
3. In the nested project, create a virtual environment with Python 3.11 and install `pip install -r requirements.txt`. Record `python --version` and `pip freeze` as an experiment environment artifact.
4. Copy `.env.example` files using `scripts/setup/init.sh`; replace every placeholder with unique local secrets and configurable host addresses. Do not commit those files.
5. Prepare raw IoT-23 outside the checkout using `IOT23_DATA_DIR=/external/path ./scripts/research/prepare-iot23.sh --download`. Download is opt-in. Validate with `PYTHONPATH=model-lab python -m model_lab.datasets.validate_iot23 research/datasets/iot23/prepared/normalized/flows.jsonl`.
6. Run an experiment from the recorded commit using `scripts/research/run-iot23-experiment.sh`. Preserve the prepared JSONL checksum and all generated artifacts; never edit result metrics manually.
7. For physical validation, use `DEMO.md`, run `scripts/testing/preflight-lab.sh`, capture resource/latency evidence, and use the robustness protocol. Record actual image digests, Docker/Compose versions, hardware, OS, clock synchronization, and IDs.

## Artifact policy

Experiment outputs identify the dataset category, version/hash, label provenance, feature version, algorithm, parameters, seed, split, sample counts, code commit, timestamp, environment, and validity. Raw IoT-23 and local experiment outputs remain outside Git/ignored. A clean checkout plus the same raw data checksum and dependency files is necessary but not sufficient: compare all environment fields before treating repeated runs as reproducible.
