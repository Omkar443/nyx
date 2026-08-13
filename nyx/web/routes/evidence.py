"""
NYX Web API Evidence Routes
"""
from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status, Body

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.application.evidence_service import EvidenceService
from nyx.web.dependencies import get_evidence_service

router = APIRouter(prefix="/api/v1", tags=["Evidence"])


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


@router.get("/evidence/{evidence_id}", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_evidence(
    evidence_id: str,
    service: EvidenceService = Depends(get_evidence_service),
) -> Dict[str, Any]:
    """Retrieve details and sanitized content for an evidence artifact ID."""
    ok, data = _parse_res(service.show(evidence_id))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": data.get("code", "NOT_FOUND"), "message": data.get("error") or data.get("message", f"Evidence '{evidence_id}' not found.")},
        )
    return {"success": True, "data": data}


@router.get("/findings/{finding_id}/evidence", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_finding_evidence(
    finding_id: str,
    service: EvidenceService = Depends(get_evidence_service),
) -> Dict[str, Any]:
    """List all evidence artifacts attached to a finding ID."""
    _, data = _parse_res(service.list_evidence(finding_id=finding_id))
    return {"success": True, "data": data}


@router.post("/findings/{finding_id}/evidence", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def add_finding_evidence(
    finding_id: str,
    payload: Dict[str, Any] = Body(...),
    service: EvidenceService = Depends(get_evidence_service),
) -> Dict[str, Any]:
    """Add note/evidence artifact to a finding ID."""
    ev_type = payload.get("ev_type", "note")
    content = payload.get("content", "")
    description = payload.get("description", "")

    ok, data = _parse_res(service.add(finding_id=finding_id, ev_type=ev_type, content=content, description=description))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "ADD_FAILED"), "message": data.get("error") or data.get("message", "Failed to add evidence.")},
        )

    ev_id = data.get("evidence_id") or data.get("data", {}).get("evidence_id", "EV-UNKNOWN")
    res_data = dict(data)
    res_data["evidence_id"] = ev_id

    await emit_event(
        event_type="evidence_added",
        data={"finding_id": finding_id, "evidence_id": ev_id},
    )
    return {"success": True, "data": res_data, "evidence_id": ev_id}


@router.post("/evidence/{evidence_id}/verify", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def verify_evidence_hash(
    evidence_id: str,
    service: EvidenceService = Depends(get_evidence_service),
) -> Dict[str, Any]:
    """Verify SHA-256 integrity hash of evidence item against stored file hash."""
    ok, data = _parse_res(service.verify(evidence_id))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "VERIFICATION_FAILED"), "message": data.get("error") or data.get("message", "Verification failed.")},
        )
    return {"success": True, "data": data}
