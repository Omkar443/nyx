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
    target: str | None = Query(None, description="Target domain"),
    service: AgentService = Depends(get_agent_service),
) -> Dict[str, Any]:
    """Retrieve reasoning context for autonomous agent."""
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target() or "No active target"
    _, data = _parse_res(service.get_context(active_target))
    return data


@router.get("/plan", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_agent_plan(
    target: str | None = Query(None, description="Target domain"),
    service: AgentService = Depends(get_agent_service),
) -> Dict[str, Any]:
    """Generate structured research plan."""
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target() or "No active target"
    _, data = _parse_res(service.plan_mission(active_target))
    return data


@router.post("/propose", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def propose_agent_action(
    target: Optional[str] = Query(None, description="Target domain"),
    action: Optional[str] = Query(None, description="Proposed action description"),
    reason: Optional[str] = Query(None, description="Reason for proposed action"),
    tool_name: Optional[str] = Query(None, description="Tool name"),
    risk: Optional[str] = Query(None, description="Risk level"),
    body: Optional[Dict[str, Any]] = None,
    service: AgentService = Depends(get_agent_service),
) -> Dict[str, Any]:
    """Propose an active execution action for human approval."""
    b = body or {}
    eff_target = b.get("target") or target or "target"
    eff_action = b.get("action") or action or "Proposed Action"
    eff_reason = b.get("reason") or reason or "Operator review required."
    eff_tool = b.get("tool_name") or b.get("tool") or tool_name or "nuclei"
    eff_risk = b.get("risk") or risk or "Medium"
    step = b.get("step")
    impact_class = b.get("impact_class")
    impact_justification = b.get("impact_justification")

    _, data = _parse_res(service.propose_action(
        target=eff_target,
        action=eff_action,
        reason=eff_reason,
        tool_name=eff_tool,
        risk=eff_risk,
        step=step,
        impact_class=impact_class,
        impact_justification=impact_justification,
    ))
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
