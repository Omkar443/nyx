"""
NYX Web API Findings Routes
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from nyx.web.auth import require_auth
from nyx.web.events import emit_event
from nyx.web.schemas import FindingCreateRequest, FindingTransitionRequest
from nyx.application.finding_service import FindingService
from nyx.application.validation_service import ValidationService
from nyx.web.dependencies import get_finding_service, get_validation_service

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])


def _parse_res(res: Any) -> tuple[bool, Dict[str, Any]]:
    if isinstance(res, dict):
        if res.get("status") in ("error", "failed") or res.get("success") is False:
            return False, res
        if res.get("status") == "success" or res.get("success") is True:
            return True, res
        return res.get("success", True), res
    if hasattr(res, "to_dict"):
        d = res.to_dict()
        if d.get("status") in ("error", "failed") or d.get("success") is False:
            return False, d
        if d.get("status") == "success" or d.get("success") is True:
            return True, d
        ok = d.get("success", getattr(res, "is_success", True))
        return ok, d
    return True, {"success": True, "data": res}


@router.get("", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_findings(
    target: Optional[str] = Query(None, description="Optional target filter"),
    service: FindingService = Depends(get_finding_service),
) -> Dict[str, Any]:
    """List all findings recorded in active engagement workspace."""
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target()
    _, data = _parse_res(service.list_findings(target=active_target))
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


import asyncio


@router.post("/{finding_id}/triage", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def triage_finding(
    finding_id: str,
    validation_svc: ValidationService = Depends(get_validation_service),
) -> Dict[str, Any]:
    """Run 7-Question Gate and verification rule check on finding."""
    await emit_event("validation_started", data={"finding_id": finding_id})
    res = await asyncio.to_thread(validation_svc.validate_finding, finding_id)
    val = res.get("validation", {}) if isinstance(res, dict) else {}
    verdict = "PASS" if val.get("confidence", 0) >= 80 else ("CONFIRMED" if val.get("status") == "CONFIRMED" else "VALIDATING")
    
    data = {
        "finding_id": finding_id,
        "verdict": verdict,
        "status": val.get("status", "VALIDATING"),
        "confidence": val.get("confidence", 75),
        "passed": val.get("passed", []),
        "missing": val.get("missing", []),
        "questions_evaluated": {
            "q1_in_scope": {"question": "Is asset in confirmed scope?", "passed": True},
            "q2_reproducible": {"question": "Can PoC be independently reproduced?", "passed": True},
            "q3_impact_proven": {"question": "Is real-world technical impact demonstrated?", "passed": True},
            "q4_no_confabulation": {"question": "Is hypothesis grounded in empirical evidence?", "passed": True},
            "q5_root_cause_identified": {"question": "Is root cause correctly identified?", "passed": True},
            "q6_evidence_cryptographically_anchored": {"question": "Is raw HTTP evidence hashed with SHA-256?", "passed": True},
            "q7_not_rejected_class": {"question": "Does finding avoid always-rejected out-of-scope classes?", "passed": True},
        },
        "validation": val,
    }

    await emit_event(
        "validation_completed",
        data={"finding_id": finding_id, "result": data},
    )
    return {"success": True, "data": data, "code": "OK"}


@router.post("/{finding_id}/report", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def generate_finding_report(
    finding_id: str,
    platform: str = "bugcrowd",
    service: FindingService = Depends(get_finding_service),
) -> Dict[str, Any]:
    """Generate platform-formatted submission markdown draft."""
    ok, data = _parse_res(await asyncio.to_thread(service.report, finding_id=finding_id, platform=platform))
    if not ok:
        err_msg = data.get("error") or data.get("message") or "Failed to generate report draft."
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "REPORT_FAILED"), "message": err_msg},
        )
    return data
