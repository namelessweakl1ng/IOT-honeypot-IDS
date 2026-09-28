from fastapi import APIRouter
from ..elastic import store
from .common import one
router=APIRouter(prefix="/detections",tags=["detections"])
@router.get("")
async def detections(): return await store.search("trapsig-detections-*",size=200)
@router.get("/{document_id}")
async def detection(document_id:str): return await one("trapsig-detections-*",document_id)
