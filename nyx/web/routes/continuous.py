"""
NYX Web API Continuous Intelligence Routes
Exposes monitoring jobs, asset history, change detection, alerts, research opportunities, and knowledge protection endpoints.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Query, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.application.continuous_service import ContinuousService

router = APIRouter(prefix="/api/v1/continuous", tags=["Continuous Security Intelligence"])


def get_continuous_service() -> ContinuousService:
    return ContinuousService()


def _parse_res(res: Any) -> tuple[bool, Dict[str, Any]]:
    if isinstance(res, dict):
        status_val = res.get("status")
        success_val = res.get("success")
        if success_val is not None:
            ok = bool(success_val)
        elif status_val is not None:
            ok = (status_val == "success" or status_val == "ok")
        else:
            ok = True
        return ok, res
    if hasattr(res, "to_dict"):
        d = res.to_dict()
        ok = d.get("success", getattr(res, "is_success", True))
        return ok, d
    return True, {"success": True, "data": res}


@router.post("/monitor/start", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def start_monitoring_job(
    target: str | None = Query(None, description="Target domain"),
    job_type: str = Query("recon_refresh", description="Monitoring job type"),
    service: ContinuousService = Depends(get_continuous_service),
) -> Dict[str, Any]:
    """Start a continuous monitoring job."""
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target() or "No active target"
    _, data = _parse_res(service.start_monitoring_job(target=active_target, job_type=job_type))
    await emit_event("monitoring_job_started", data={"target": active_target, "job_type": job_type})
    return data


@router.get("/monitor/status", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_monitoring_status(service: ContinuousService = Depends(get_continuous_service)) -> Dict[str, Any]:
    """Get active monitoring jobs status."""
    _, data = _parse_res(service.get_monitoring_status())
    return data


@router.get("/assets/history", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_asset_history(
    target: str | None = Query(None, description="Target filter"),
    service: ContinuousService = Depends(get_continuous_service),
) -> Dict[str, Any]:
    """Get historical asset graph snapshots."""
    _, data = _parse_res(service.get_asset_history(target=target))
    return data


@router.get("/changes", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_changes(
    target: str | None = Query(None, description="Target filter"),
    service: ContinuousService = Depends(get_continuous_service),
) -> Dict[str, Any]:
    """List detected security change events."""
    _, data = _parse_res(service.list_changes(target=target))
    return data


@router.get("/alerts", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_alerts(
    target: str | None = Query(None, description="Target filter"),
    service: ContinuousService = Depends(get_continuous_service),
) -> Dict[str, Any]:
    """List active security alerts."""
    _, data = _parse_res(service.list_alerts(target=target))
    return data


@router.get("/research/opportunities", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_research_opportunities(
    target: str | None = Query(None, description="Target filter"),
    service: ContinuousService = Depends(get_continuous_service),
) -> Dict[str, Any]:
    """List prioritized security research opportunities."""
    _, data = _parse_res(service.list_research_opportunities(target=target))
    return data


@router.post("/knowledge/backup", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def backup_knowledge(service: ContinuousService = Depends(get_continuous_service)) -> Dict[str, Any]:
    """Create a backup of skills and knowledge assets."""
    _, data = _parse_res(service.backup_knowledge())
    return data


@router.get("/knowledge/verify", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def verify_knowledge(service: ContinuousService = Depends(get_continuous_service)) -> Dict[str, Any]:
    """Verify integrity and YAML frontmatter of knowledge assets."""
    _, data = _parse_res(service.verify_knowledge())
    return data
