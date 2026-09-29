from fastapi import APIRouter
from ..config import get_settings
from ..elastic import store
from ..services.pi_manager import pi_manager
from ..services import processor as processor_module
router=APIRouter()
@router.get("/health")
async def health():
    try: elastic=(await store.health()).get("status","unknown")
    except Exception: elastic="unavailable"
    return {"backend":"healthy","elasticsearch":elastic}
@router.get("/system/status")
async def status():
    cfg=get_settings(); data=await health()
    statuses=await pi_manager.statuses()
    async def count(index:str)->int:
        return await store.count(index, missing_index_is_empty=True)
    return {**data,"logstash":"configured","kibana_url":cfg.kibana_url,"pi":"reachable" if any(value!="unreachable" for value in statuses.values()) else "unreachable","honeypots":statuses,"counts":{"events":await count("trapsig-events-*"),"sessions":await count("trapsig-sessions"),"detections":await count("trapsig-detections"),"experiments":await count("trapsig-experiments"),"dead_letter":await count("trapsig-dead-letter-*")},"processor":processor_module.processor.status() if processor_module.processor else {"last_run":None}}
