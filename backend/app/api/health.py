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
    async def safe_count(index:str)->int|None:
        try:return await store.count(index)
        except Exception:return 0
    return {**data,"logstash":"configured","kibana_url":cfg.kibana_url,"pi":"reachable" if any(value!="unreachable" for value in statuses.values()) else "unreachable","honeypots":statuses,"counts":{"events":await safe_count("trapsig-events-*"),"sessions":await safe_count("trapsig-sessions"),"detections":await safe_count("trapsig-detections"),"experiments":await safe_count("trapsig-experiments"),"dead_letter":await safe_count("trapsig-dead-letter-*")},"processor":processor_module.processor.status() if processor_module.processor else {"last_run":None}}
