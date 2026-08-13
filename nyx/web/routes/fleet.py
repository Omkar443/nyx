"""
NYX Web API Fleet REST Routes
Exposes multi-agent control, agent creation/stopping, task queue, and fleet status endpoints.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.application.fleet_service import FleetService

router = APIRouter(prefix="/api/v1/fleet", tags=["Multi-Agent Fleet"])


def get_fleet_service() -> FleetService:
    return FleetService()


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


@router.get("/agents", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_fleet_agents(
    target: Optional[str] = Query(None, description="Target domain filter"),
    agent_type: Optional[str] = Query(None, description="Agent type filter"),
    service: FleetService = Depends(get_fleet_service),
) -> Dict[str, Any]:
    """List active agents in multi-agent fleet."""
    _, data = _parse_res(service.list_agents(target=target, agent_type=agent_type))
    return data


@router.post("/agents", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def create_fleet_agent(
    type: str = Query("recon", description="Agent type (recon|web|api|technology|validation|reporting)"),
    target: str = Query("example.com", description="Target domain"),
    service: FleetService = Depends(get_fleet_service),
) -> Dict[str, Any]:
    """Create and launch a new specialized agent."""
    _, data = _parse_res(service.create_agent(type=type, target=target))
    await emit_event("agent_started", data={"agent_type": type, "target": target})
    return data


@router.post("/agents/{agent_id}/stop", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def stop_fleet_agent(
    agent_id: str,
    service: FleetService = Depends(get_fleet_service),
) -> Dict[str, Any]:
    """Stop and unregister an active agent."""
    ok, data = _parse_res(service.stop_agent(agent_id))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "AGENT_NOT_FOUND", "message": f"Agent '{agent_id}' not found."},
        )
    return data


@router.get("/tasks", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_fleet_tasks(
    status: Optional[str] = Query(None, description="Status filter"),
    service: FleetService = Depends(get_fleet_service),
) -> Dict[str, Any]:
    """List tasks in distributed task queue."""
    _, data = _parse_res(service.list_tasks(status=status))
    return data


@router.post("/tasks", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def create_fleet_task(
    task_type: str = Query(..., description="Task type"),
    target: str = Query(..., description="Target domain"),
    agent_type: str = Query("recon", description="Target agent type"),
    priority: int = Query(5, description="Priority 1-10"),
    service: FleetService = Depends(get_fleet_service),
) -> Dict[str, Any]:
    """Enqueue a new task into the distributed queue."""
    _, data = _parse_res(service.create_task(task_type=task_type, target=target, agent_type=agent_type, priority=priority))
    return data


@router.post("/multi-start", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def multi_start_mission(
    targets: List[str] = Query(["example.com"], description="Target domains"),
    service: FleetService = Depends(get_fleet_service),
) -> Dict[str, Any]:
    """Launch multi-agent research fleet across multiple target domains."""
    _, data = _parse_res(service.multi_start_mission(targets))
    return data


@router.get("/status", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_fleet_status(service: FleetService = Depends(get_fleet_service)) -> Dict[str, Any]:
    """Get complete fleet status and metrics."""
    _, data = _parse_res(service.get_fleet_status())
    return data
