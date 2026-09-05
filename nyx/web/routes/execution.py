"""
NYX Web API Tool Execution Routes
"""
from __future__ import annotations

from typing import Any, Dict, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.web.schemas import ExecutionRequestSchema
from nyx.application.execution_service import ExecutionService
from nyx.web.dependencies import get_execution_service

router = APIRouter(prefix="/api/v1/execution", tags=["Execution Engine"])


def _parse_res(res: Any) -> tuple[bool, Dict[str, Any]]:
    if isinstance(res, dict):
        return res.get("success", True), res
    if hasattr(res, "to_dict"):
        d = res.to_dict()
        ok = d.get("success", getattr(res, "is_success", True))
        return ok, d
    return True, {"success": True, "data": res}


@router.get("/history", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_execution_history(
    limit: int = Query(50, ge=1, le=500),
    target: str | None = Query(None, description="Optional target domain to filter executions"),
    service: ExecutionService = Depends(get_execution_service),
) -> Dict[str, Any]:
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target()
    _, data = _parse_res(service.get_history(limit=limit, target=active_target))
    return data


@router.get("/{execution_id}", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_execution_status(
    execution_id: str,
    service: ExecutionService = Depends(get_execution_service),
) -> Dict[str, Any]:
    """Retrieve execution status and stored output artifacts."""
    ok, data = _parse_res(service.get_status(execution_id))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": data.get("code", "NOT_FOUND"), "message": data.get("error", f"Execution '{execution_id}' not found.")},
        )
    return data


@router.post("/run", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def run_tool_execution(
    req: ExecutionRequestSchema,
    service: ExecutionService = Depends(get_execution_service),
) -> Dict[str, Any]:
    """
    Execute a controlled security tool.
    MUST pass through scope, authorization, and execution policy checks.
    """
    await emit_event(
        event_type="execution_started",
        data={"tool": req.tool_name, "target": req.target, "dry_run": req.dry_run},
    )

    import asyncio
    tool_res = await asyncio.to_thread(
        service.run_tool,
        tool_name=req.tool_name,
        target=req.target,
        arguments=req.arguments,
        dry_run=req.dry_run,
        active_permitted=req.active_permitted,
    )
    ok, data = _parse_res(tool_res)

    await emit_event(
        event_type="execution_finished",
        data={
            "tool": req.tool_name,
            "target": req.target,
            "status": data.get("data", {}).get("status") if ok else "FAILED",
        },
    )

    if not ok:
        exec_data = data.get("data", {})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": data.get("code", "EXECUTION_BLOCKED"),
                "message": data.get("error", f"Execution of '{req.tool_name}' failed or was blocked."),
                "status": exec_data.get("status", "FAILED"),
                "exit_code": exec_data.get("exit_code", 1),
                "details": exec_data,
            },
        )

    return data


@router.post("/enqueue", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def enqueue_tool_execution(
    req: ExecutionRequestSchema,
    priority: int = Query(10, ge=1, le=10),
    service: ExecutionService = Depends(get_execution_service),
) -> Dict[str, Any]:
    """Enqueue a tool execution request into priority execution queue."""
    _, data = _parse_res(service.enqueue_tool(
        tool_name=req.tool_name,
        target=req.target,
        arguments=req.arguments,
        priority=priority,
        dry_run=req.dry_run,
    ))
    return data
