from datetime import datetime,timezone
from uuid import uuid4
from fastapi import APIRouter,HTTPException
from ..elastic import store
from ..schemas import ExperimentCreate
from ..services.experiments import correlate
from .common import one
router=APIRouter(prefix="/experiments",tags=["experiments"])
INDEX="trapsig-experiments"
@router.get("")
async def experiments():
    return await store.search(
        INDEX,
        size=200,
        sort_field="created_at",
        missing_index_is_empty=True,
    )
@router.post("",status_code=201)
async def create(payload:ExperimentCreate):
    identifier="EXP-"+uuid4().hex[:12].upper(); doc={**payload.model_dump(),"experiment_id":identifier,"status":"created","created_at":datetime.now(timezone.utc).isoformat()}
    return await store.save(INDEX,identifier,doc)
@router.get("/{identifier}")
async def experiment(identifier:str): return await one("trapsig-experiments",identifier)
@router.post("/{identifier}/start")
async def start(identifier:str):
    doc=await experiment(identifier)
    if doc["status"]!="created": raise HTTPException(409,"experiment is not in created state")
    doc.update(status="running",start_time=datetime.now(timezone.utc).isoformat()); doc.pop("_id",None)
    return await store.save(INDEX,identifier,doc)
@router.post("/{identifier}/finish")
async def finish(identifier:str):
    doc=await experiment(identifier)
    if doc["status"]!="running": raise HTTPException(409,"experiment is not running")
    doc.update(status="completed",end_time=datetime.now(timezone.utc).isoformat()); doc.pop("_id",None)
    from ..services import processor as processor_module
    if processor_module.processor:
        await processor_module.processor.process_once()
    events=await store.search("trapsig-events-*",size=500,sort_field="@timestamp"); sessions=await store.search("trapsig-sessions",size=500,sort_field="start_time"); detections=await store.search("trapsig-detections",size=500,sort_field="timestamp")
    return await store.save(INDEX,identifier,correlate(doc,events,sessions,detections))
