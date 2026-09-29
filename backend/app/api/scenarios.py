from fastapi import APIRouter, HTTPException

from ..services.scenarios import ScenarioCatalog, ScenarioCatalogError

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


@router.get("")
async def scenarios():
    try:
        return [scenario.public_dict() for scenario in ScenarioCatalog().load().values()]
    except ScenarioCatalogError as exc:
        raise HTTPException(500, f"scenario catalog is invalid: {exc}") from exc
