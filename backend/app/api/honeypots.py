from fastapi import APIRouter,HTTPException
from ..services.pi_manager import HONEYPOTS,pi_manager
router=APIRouter(prefix="/honeypots",tags=["honeypots"])
@router.get("")
async def honeypots(): return [{"id":key,**value,"status":"unknown"} for key,value in HONEYPOTS.items()]
async def run(identifier:str,action:str):
    try:return await pi_manager.action(identifier,action)
    except ValueError as exc: raise HTTPException(404,str(exc)) from exc
    except RuntimeError as exc: raise HTTPException(503,str(exc)) from exc
@router.post("/{identifier}/start")
async def start(identifier:str):return await run(identifier,"start")
@router.post("/{identifier}/stop")
async def stop(identifier:str):return await run(identifier,"stop")
@router.post("/{identifier}/restart")
async def restart(identifier:str):return await run(identifier,"restart")
