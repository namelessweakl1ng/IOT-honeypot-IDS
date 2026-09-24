# Custom dashboard (React + TypeScript)

A small companion dashboard focused on what Kibana does *not* conveniently
provide: ML status, model registry, experiments, replay controls.

Kibana remains the primary visualization layer for raw events.

## Develop

```bash
cd dashboard/frontend
npm install
npm run dev
```

Open http://localhost:3000

## Build static assets (production)

```bash
npm run build
# serve the dist/ folder via nginx or the FastAPI service
```

## Environment

Vite reads these from `.env` (or the docker-compose `environment:` block):

- `VITE_API_URL` — base URL of the FastAPI service (default: `http://localhost:8000`)
- `VITE_KIBANA_URL` — Kibana URL for the "Open Kibana" link
