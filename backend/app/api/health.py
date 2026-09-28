from fastapi import APIRouter
from ..config import get_settings
from ..elastic import store
router=APIRouter()
@router.get("/health")
async def health():
    try: elastic=(await store.health()).get("status","unknown")
    except Exception: elastic="unavailable"
    return {"backend":"healthy","elasticsearch":elastic}
@router.get("/system/status")
async def status():
    cfg=get_settings(); data=await health()
    return {**data,"kibana_url":cfg.kibana_url,"pi_configured":bool(cfg.pi_host),"lab_subnet":cfg.lab_subnet}
