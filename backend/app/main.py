from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import analytics, detections, events, experiments, health, honeypots, scenarios, sessions
from .config import get_settings
from .elastic import store
from .services.processor import configure_processor


@asynccontextmanager
async def lifespan(app: FastAPI):
    processor = configure_processor(store)
    processor.start()
    yield
    await processor.stop()
    await store.close()


app = FastAPI(title="TRAPSIG API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=get_settings().cors_origins.split(","), allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
for router in [health.router, analytics.router, events.router, sessions.router, detections.router, experiments.router, honeypots.router, scenarios.router]:
    app.include_router(router)
