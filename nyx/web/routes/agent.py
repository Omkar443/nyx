"""
NYX Web API Autonomous Agent Routes
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.application.agent_service import AgentService

router = APIRouter(prefix="/api/v1/agent", tags=["Autonomous Agent"])


def get_agent_service() -> AgentService:
    return AgentService()


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


@router.post("/start", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def start_agent_mission(
    target: str = Query(..., description="Target domain"),
    service: AgentService = Depends(get_agent_service),
) -> Dict[str, Any]:
    """Start autonomous agent research mission."""
    _, data = _parse_res(service.start_mission(target))
    await emit_event("mission_started", data={"target": target, "agent": True})
    return data


@router.get("/context", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_agent_context(
    target: str = Query("example.com", description="Target domain"),
    service: AgentService = Depends(get_agent_service),
) -> Dict[str, Any]:
    """Retrieve reasoning context for autonomous agent."""
    _, data = _parse_res(service.get_context(target))
    return data


@router.get("/plan", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_agent_plan(
    target: str = Query("example.com", description="Target domain"),
    service: AgentService = Depends(get_agent_service),
) -> Dict[str, Any]:
    """Generate structured research plan."""
    _, data = _parse_res(service.plan_mission(target))
    return data


@router.post("/propose", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def propose_agent_action(
    target: str = Query(..., description="Target domain"),
    action: str = Query(..., description="Proposed action description"),
    reason: str = Query(..., description="Reason for proposed action"),
    tool_name: str = Query("subfinder", description="Tool name"),
    risk: str = Query("Medium", description="Risk level"),
    service: AgentService = Depends(get_agent_service),
) -> Dict[str, Any]:
    """Propose an active execution action for human approval."""
    _, data = _parse_res(service.propose_action(target=target, action=action, reason=reason, tool_name=tool_name, risk=risk))
    return data


@router.get("/approvals", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_pending_approvals(service: AgentService = Depends(get_agent_service)) -> Dict[str, Any]:
    """Get list of pending action approval requests."""
    _, data = _parse_res(service.get_approvals())
    return data


@router.post("/approve/{action_id}", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def approve_agent_action(
    action_id: str,
    service: AgentService = Depends(get_agent_service),
) -> Dict[str, Any]:
    """Approve a pending action ID."""
    ok, data = _parse_res(service.approve_action(action_id))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "APPROVAL_FAILED", "message": data.get("error", "Approval failed.")},
        )
    return data


@router.post("/deny/{action_id}", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def deny_agent_action(
    action_id: str,
    reason: str = Query("", description="Reason for denial"),
    service: AgentService = Depends(get_agent_service),
) -> Dict[str, Any]:
    """Deny a pending action ID."""
    ok, data = _parse_res(service.deny_action(action_id, reason=reason))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "DENIAL_FAILED", "message": data.get("error", "Denial failed.")},
        )
    return data


@router.get("/status", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_agent_status(service: AgentService = Depends(get_agent_service)) -> Dict[str, Any]:
    """Get current agent status and pending approval queue count."""
    _, data = _parse_res(service.get_status())
    return data
