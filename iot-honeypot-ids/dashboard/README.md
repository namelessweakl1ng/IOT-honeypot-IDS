# Dashboard — Computer 1 (ELK + ML + API + Frontend)

This is the central analysis machine. It runs:

1. **Elasticsearch + Logstash + Kibana** (the ELK stack, pinned to a
   single aligned version).
2. **FastAPI service** — exposes sessions, detections, models, experiments
   over a clean REST API.
3. **ML service / pipeline** — feature extraction, training, evaluation,
   anomaly detection, model registry.
4. **React + TypeScript custom dashboard** — small UI focused on what
   Kibana does not conveniently provide (ML status, model comparison,
   replay controls).

The whole stack starts with:

```bash
cd dashboard
cp .env.example .env
docker compose up -d
```

## Components

| Folder                       | What lives here                                  |
|------------------------------|--------------------------------------------------|
| `elasticsearch/`             | ES config, index templates, ILM policies         |
| `logstash/`                  | Pipeline configs (input / filter / output)       |
| `kibana/`                    | Kibana config + saved-objects export             |
| `api/`                       | FastAPI service (sessions/detections/models)     |
| `ml/`                        | Feature extraction + training + evaluation code  |
| `frontend/`                  | React + TS custom dashboard                      |
| `config/`                    | Cross-service config (CORS, auth, etc.)          |

## Endpoints after start

- Kibana: `http://<PC1_IP>:5601`
- FastAPI docs: `http://<PC1_IP>:8000/docs`
- FastAPI health: `http://<PC1_IP>:8000/health`
- Frontend: `http://<PC1_IP>:3000` (dev server) or via API reverse-proxy
  in production (see `docker compose` profile `prod`).

## Operating-system support

The compose file is platform-independent. The only OS-specific bits are the
helper scripts that wrap `docker compose`:

- Bash (`.sh`) — used on Fedora Linux.
- PowerShell (`.ps1`) — used on Windows.

Both delegate to the same `docker compose` commands, so behaviour is identical.

See [`../docs/deployment/`](../docs/deployment/) for per-OS setup details.
