"""
NYX Web API Attack Surface Routes
"""
from __future__ import annotations

from typing import Any, Dict, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.application.analysis_service import AnalysisService
from nyx.application.recon_service import ReconService
from nyx.web.dependencies import get_analysis_service, get_recon_service

router = APIRouter(prefix="/api/v1", tags=["Attack Surface"])


def _parse_res(res: Any) -> tuple[bool, Dict[str, Any]]:
    if isinstance(res, dict):
        return res.get("success", True), res
    if hasattr(res, "to_dict"):
        d = res.to_dict()
        ok = d.get("success", getattr(res, "is_success", True))
        return ok, d
    return True, {"success": True, "data": res}


@router.get("/surface", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_attack_surface(
    target: str | None = Query(None, description="Target domain"),
    service: AnalysisService = Depends(get_analysis_service),
) -> Dict[str, Any]:
    """Get attack surface ranking for target."""
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target() or "No active target"
    ok, data = _parse_res(service.rank_surface(target=active_target))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "SURFACE_ERROR"), "message": data.get("error", "Error analyzing surface.")},
        )
    return data


@router.get("/endpoints", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_endpoints(
    target: Optional[str] = Query(None, description="Optional target filter"),
    service: ReconService = Depends(get_recon_service),
) -> Dict[str, Any]:
    """Retrieve harvested endpoint inventory from engagement memory."""
    _, data = _parse_res(service.get_endpoints(target=target))
    return data


@router.get("/technologies", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_technologies(service: ReconService = Depends(get_recon_service)) -> Dict[str, Any]:
    """Retrieve detected technology stack from engagement memory."""
    _, data = _parse_res(service.get_technologies())
    return data


@router.get("/assets", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_assets(
    target: Optional[str] = Query(None, description="Optional target filter"),
    service: ReconService = Depends(get_recon_service),
) -> Dict[str, Any]:
    """Retrieve target asset surface overview."""
    _, eps_data = _parse_res(service.get_endpoints(target=target))
    _, tech_data = _parse_res(service.get_technologies())

    eps = eps_data.get("data", {}).get("endpoints", []) if isinstance(eps_data.get("data"), dict) else eps_data.get("endpoints", [])
    techs = tech_data.get("data", {}).get("technologies", []) if isinstance(tech_data.get("data"), dict) else tech_data.get("technologies", [])
    if not isinstance(techs, list):
        if isinstance(techs, dict):
            flat_t = []
            for v in techs.values():
                if isinstance(v, list):
                    flat_t.extend(v)
            techs = sorted(list(set(flat_t)))
        else:
            techs = []

    return {
        "success": True,
        "data": {
            "endpoints_count": len(eps) if isinstance(eps, list) else 0,
            "technologies_count": len(techs) if isinstance(techs, list) else 0,
            "endpoints": eps[:50] if isinstance(eps, list) else [],
            "technologies": techs if isinstance(techs, list) else [],
        },
        "error": None,
        "code": "OK",
    }


@router.post("/surface/recon", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def run_recon_surface(
    target: str = Query(..., description="Target domain"),
    service: ReconService = Depends(get_recon_service),
) -> Dict[str, Any]:
    """Run passive reconnaissance workflow."""
    from nyx.execution.policy import normalize_target
    target_clean = normalize_target(target)
    await emit_event("recon_started", data={"target": target_clean})
    res = await asyncio.to_thread(service.run_recon, target=target_clean)
    ok, data = _parse_res(res)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "RECON_FAILED"), "message": data.get("error", "Recon failed.")},
        )

    await emit_event("recon_completed", data={"target": target_clean, "results": data.get("data", {})})
    return data
