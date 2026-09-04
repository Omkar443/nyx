"""
NYX Web API Mission & Engagement Routes
"""
from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.web.schemas import MissionInitRequest, MissionStateRequest
from nyx.application.engagement_service import EngagementService
from nyx.web.dependencies import get_engagement_service

router = APIRouter(prefix="/api/v1/mission", tags=["Mission"])


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


@router.get("", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_mission(service: EngagementService = Depends(get_engagement_service)) -> Dict[str, Any]:
    """Get active engagement mission status and current state."""
    ok, data = _parse_res(service.get_status())
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": data.get("code", "NOT_FOUND"), "message": data.get("message", "No active engagement mission found.")},
        )
    res_data = dict(data)
    res_data["state"] = res_data.get("state") or res_data.get("curr_state")
    return {"success": True, "data": res_data}


@router.post("", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def init_mission(
    req: MissionInitRequest,
    service: EngagementService = Depends(get_engagement_service),
) -> Dict[str, Any]:
    """Initialize or reset an engagement mission workspace."""
    from nyx.execution.policy import normalize_target
    target_clean = normalize_target(req.target)
    ok, data = _parse_res(service.init_engagement(target=target_clean, reset=req.reset, force=req.force))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "INIT_FAILED"), "message": data.get("message", "Failed to initialize mission.")},
        )

    await emit_event(
        event_type="mission_started",
        data={"target": target_clean, "action": "init"},
        mission_id=target_clean,
    )
    return {"success": True, "data": data}


@router.post("/state", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def transition_mission_state(
    req: MissionStateRequest,
    service: EngagementService = Depends(get_engagement_service),
) -> Dict[str, Any]:
    """Transition workflow state or switch workflow mode."""
    ok, data = _parse_res(service.set_state(new_state=req.new_state, mode=req.mode, force=req.force))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "TRANSITION_FAILED"), "message": data.get("message", "State transition failed.")},
        )

    res_data = dict(data)
    res_data["state"] = res_data.get("curr_state") or res_data.get("state") or req.new_state

    await emit_event(
        event_type="phase_changed",
        data={"phase": res_data["state"], "new_state": req.new_state, "mode": req.mode},
    )
    if req.new_state == "REPORTING":
        await emit_event(
            event_type="mission_completed",
            data={"new_state": req.new_state, "mode": req.mode},
        )
    return {"success": True, "data": res_data}


@router.get("/history", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_mission_history(service: EngagementService = Depends(get_engagement_service)) -> Dict[str, Any]:
    """Retrieve engagement timeline state transition history."""
    ok, data = _parse_res(service.get_history())
    return {"success": ok, "data": data}
