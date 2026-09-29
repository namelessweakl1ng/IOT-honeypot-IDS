"""Read-only research evaluation and export endpoints."""

import json

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from ..elastic import store
from ..services.evaluation import aggregate, export_csv, export_rows

router = APIRouter(prefix="/evaluation", tags=["evaluation"])


async def _records():
    return await store.search_all("trapsig-experiments", {"match_all": {}}, sort=[{"created_at": "asc"}], missing_index_is_empty=True)


@router.get("/summary")
async def summary():
    return aggregate(await _records())


@router.get("/export.csv", response_class=PlainTextResponse)
async def csv_export():
    return PlainTextResponse(export_csv(await _records()), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=experiments.csv"})


@router.get("/export.json", response_class=PlainTextResponse)
async def json_export():
    return PlainTextResponse(
        json.dumps(export_rows(await _records()), indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=experiments.json"},
    )
