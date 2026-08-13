"""
NYX Web API Distributed Worker Routes
Exposes worker registration, worker listing, status metrics, node removal, and remote task dispatch endpoints.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.application.worker_service import WorkerService

router = APIRouter(prefix="/api/v1/workers", tags=["Distributed Workers"])


def get_worker_service() -> WorkerService:
    return WorkerService()


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
async def list_workers(
    status: Optional[str] = Query(None, description="Status filter (ONLINE|BUSY|OFFLINE|ERROR)"),
    agent_type: Optional[str] = Query(None, description="Supported agent type filter"),
    service: WorkerService = Depends(get_worker_service),
) -> Dict[str, Any]:
    """List registered worker nodes."""
    _, data = _parse_res(service.list_workers(status=status, agent_type=agent_type))
    return data


@router.post("/register", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def register_worker_node(
    hostname: str = Query("worker-node-1", description="Worker hostname"),
    service: WorkerService = Depends(get_worker_service),
) -> Dict[str, Any]:
    """Register a new remote worker node."""
    _, data = _parse_res(service.register_worker(hostname=hostname))
    await emit_event("worker_registered", data={"hostname": hostname})
    return data


@router.get("/status", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_worker_status(service: WorkerService = Depends(get_worker_service)) -> Dict[str, Any]:
    """Get aggregated worker status and health metrics."""
    _, data = _parse_res(service.get_worker_status())
    return data


@router.post("/{worker_id}/remove", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def remove_worker_node(
    worker_id: str,
    service: WorkerService = Depends(get_worker_service),
) -> Dict[str, Any]:
    """Remove a worker node from registry."""
    ok, data = _parse_res(service.remove_worker(worker_id))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "WORKER_NOT_FOUND", "message": f"Worker '{worker_id}' not found."},
        )
    return data


@router.post("/tasks/remote", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def dispatch_remote_task(
    task_id: str = Query(..., description="Task ID to dispatch"),
    service: WorkerService = Depends(get_worker_service),
) -> Dict[str, Any]:
    """Dispatch task to local agent or remote worker node."""
    ok, data = _parse_res(service.dispatch_remote_task(task_id))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "DISPATCH_FAILED", "message": data.get("error", "Dispatch failed.")},
        )
    return data
