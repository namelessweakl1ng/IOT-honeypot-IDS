from fastapi import APIRouter, Query
from ..elastic import store
from .common import one
router=APIRouter(prefix="/events",tags=["events"])
@router.get("")
async def events(size:int=Query(100,ge=1,le=500),honeypot:str|None=None,source_ip:str|None=None,protocol:str|None=None,category:str|None=None):
    filters=[]
    for field,value in [("honeypot.id",honeypot),("source.ip",source_ip),("network.protocol",protocol),("event.category",category)]:
        if value: filters.append({"term":{field:value}})
    return await store.search("trapsig-events-*",{"bool":{"filter":filters}} if filters else None,size)
@router.get("/{document_id}")
async def event(document_id:str): return await one("trapsig-events-*",document_id)
