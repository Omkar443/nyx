"""
NYX Web API Browser & Runtime Intelligence Routes
Exposes browser session management, runtime network graph, authentication flows, and dynamic agent routes.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Query, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.application.browser_service import BrowserService

router = APIRouter(prefix="/api/v1/browser", tags=["Browser & Runtime Intelligence"])


def get_browser_service() -> BrowserService:
    return BrowserService()


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
async def start_browser_session(
    target: str | None = Query(None, description="Target domain"),
    service: BrowserService = Depends(get_browser_service),
) -> Dict[str, Any]:
    """Start a new managed browser session."""
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target() or "No active target"
    _, data = _parse_res(service.start_session(target=active_target))
    await emit_event("browser_session_started", data={"target": active_target})
    return data


@router.get("/sessions", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_browser_sessions(service: BrowserService = Depends(get_browser_service)) -> Dict[str, Any]:
    """List active and stored browser sessions."""
    _, data = _parse_res(service.list_sessions())
    return data


@router.get("/runtime", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_runtime_intelligence(service: BrowserService = Depends(get_browser_service)) -> Dict[str, Any]:
    """Get the unified Runtime Intelligence Graph."""
    _, data = _parse_res(service.get_runtime_intelligence())
    return data


@router.get("/auth/flows", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_auth_flows(service: BrowserService = Depends(get_browser_service)) -> Dict[str, Any]:
    """List authentication flows and session tokens."""
    _, data = _parse_res(service.list_auth_flows())
    return data


@router.post("/agent/dynamic", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def run_dynamic_agent(
    target: str | None = Query(None, description="Target domain"),
    service: BrowserService = Depends(get_browser_service),
) -> Dict[str, Any]:
    """Run dynamic browser testing research agent."""
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target() or "No active target"
    _, data = _parse_res(service.run_dynamic_agent(target=active_target))
    await emit_event("dynamic_agent_executed", data={"target": active_target})
    return data
