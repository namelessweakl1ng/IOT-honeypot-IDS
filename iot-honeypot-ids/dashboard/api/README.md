# FastAPI service — exposes sessions, detections, models, experiments

A small Python service that reads from Elasticsearch, runs the rule engine,
orchestrates the ML pipeline (training / evaluation / replay), and exposes
everything through a clean REST API.

It is intentionally thin: heavy ML work happens in [`dashboard/ml/`](../ml/)
and [`model-lab/`](../../model-lab/).

## Run locally (development)

```bash
cd dashboard/api
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export ELASTICSEARCH_URL=http://localhost:9200
export ELASTIC_PASSWORD=changeme-elastic
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Endpoints

| Method | Path                       | Purpose                                |
|--------|----------------------------|----------------------------------------|
| GET    | `/health`                  | Liveness + downstream dependency state |
| GET    | `/events`                  | Search raw honeypot events             |
| GET    | `/sessions`                | List reconstructed sessions            |
| GET    | `/sessions/{id}`           | Full session timeline                  |
| GET    | `/detections`              | Recent detections                       |
| GET    | `/models`                  | List model registry entries            |
| GET    | `/models/{id}`             | One model metadata                     |
| GET    | `/experiments`             | List experiment runs                   |
| GET    | `/metrics`                 | Latest model metrics                    |
| POST   | `/training`                | Trigger a training run                  |
| POST   | `/replay`                  | Trigger a replay scenario              |

OpenAPI docs at `/docs`.
