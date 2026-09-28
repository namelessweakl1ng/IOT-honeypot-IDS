from fastapi import APIRouter
from ..elastic import store
from .common import one
router=APIRouter(prefix="/sessions",tags=["sessions"])
@router.get("")
async def sessions(): return await store.search("trapsig-sessions",size=200,sort_field="start_time")
@router.get("/{document_id}")
async def session(document_id:str): return await one("trapsig-sessions",document_id)
