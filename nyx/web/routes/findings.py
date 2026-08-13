"""
NYX Web API Findings Routes
"""
from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.web.schemas import FindingCreateRequest, FindingTransitionRequest
from nyx.application.finding_service import FindingService
from nyx.application.validation_service import ValidationService
from nyx.web.dependencies import get_finding_service, get_validation_service

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])


def _parse_res(res: Any) -> tuple[bool, Dict[str, Any]]:
    if isinstance(res, dict):
        return res.get("success", True), res
    if hasattr(res, "to_dict"):
        d = res.to_dict()
        ok = d.get("success", getattr(res, "is_success", True))
        return ok, d
    return True, {"success": True, "data": res}


@router.get("", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_findings(service: FindingService = Depends(get_finding_service)) -> Dict[str, Any]:
    """List all findings recorded in active engagement workspace."""
    _, data = _parse_res(service.list_findings())
    return data


@router.get("/{finding_id}", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_finding(
    finding_id: str,
    service: FindingService = Depends(get_finding_service),
) -> Dict[str, Any]:
    """Get detailed records and hypothesis data for a finding ID."""
    ok, data = _parse_res(service.get_finding(finding_id))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": data.get("code", "NOT_FOUND"), "message": data.get("error", f"Finding '{finding_id}' not found.")},
        )
    return data


@router.post("", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def create_finding(
    req: FindingCreateRequest,
    service: FindingService = Depends(get_finding_service),
) -> Dict[str, Any]:
    """Create a new finding hypothesis in HYPOTHESIS state."""
    ok, data = _parse_res(service.create_finding(
        title=req.title,
        endpoint=req.endpoint,
        parameter=req.parameter,
        vulnerability=req.vulnerability,
        severity=req.severity,
        description=req.description,
        tags=req.tags,
    ))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "CREATE_FAILED"), "message": data.get("error", "Failed to create finding.")},
        )

    f_id = data.get("data", {}).get("finding_id") or data.get("finding_id", "FH-UNKNOWN")
    await emit_event(
        event_type="finding_created",
        data={"finding_id": f_id, "title": req.title, "severity": req.severity},
    )
    return data


@router.post("/{finding_id}/transition", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def transition_finding(
    finding_id: str,
    req: FindingTransitionRequest,
    service: FindingService = Depends(get_finding_service),
) -> Dict[str, Any]:
    """Transition finding state machine with mandatory justification reason."""
    ok, data = _parse_res(service.transition_state(finding_id=finding_id, new_state=req.new_state, reason=req.reason))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "TRANSITION_FAILED"), "message": data.get("error", "Finding state transition failed.")},
        )

    await emit_event(
        event_type="finding_updated",
        data={"finding_id": finding_id, "new_state": req.new_state, "reason": req.reason},
    )
    return data


@router.post("/{finding_id}/triage", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def triage_finding(
    finding_id: str,
    validation_svc: ValidationService = Depends(get_validation_service),
) -> Dict[str, Any]:
    """Run 7-Question Gate and verification rule check on finding."""
    await emit_event("validation_started", data={"finding_id": finding_id})
    _, data = _parse_res(validation_svc.validate_finding(finding_id))

    await emit_event(
        "validation_completed",
        data={"finding_id": finding_id, "result": data.get("data", {})},
    )
    return data


@router.post("/{finding_id}/report", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def generate_finding_report(
    finding_id: str,
    platform: str = "bugcrowd",
    service: FindingService = Depends(get_finding_service),
) -> Dict[str, Any]:
    """Generate platform-formatted submission markdown draft."""
    ok, data = _parse_res(service.report(finding_id=finding_id, platform=platform))
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "REPORT_FAILED"), "message": data.get("error", "Failed to generate report draft.")},
        )
    return data
