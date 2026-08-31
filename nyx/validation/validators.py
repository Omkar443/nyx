"""
NYX Validation Engine Validators Module
"""
from __future__ import annotations
from nyx.validation.rules import get_rule
from nyx.validation.confidence import calculate_confidence


def validate_finding_data(type_str: str, endpoint: str = "", parameter: str = "", evidence: list[dict] | None = None) -> dict:
    rule = get_rule(type_str)
    ev_list = evidence or []

    if not rule:
        # Fallback generic rule
        rule = {
            "type": type_str,
            "category": "general",
            "required_evidence": ["http_request", "http_response"],
            "checklist": ["Endpoint input verification", "Response differential"],
            "base_confidence": 30
        }

    finding_meta = {"endpoint": endpoint, "parameter": parameter}
    conf, passed, missing = calculate_confidence(rule, ev_list, finding_meta)

    # Check if any AI review evidence is present confirming or rejecting
    has_ai_confirmed = any(
        isinstance(e, dict) and e.get("type") == "ai_review" and "CONFIRMED" in str(e.get("content") or e.get("data") or "")
        for e in ev_list
    )
    has_ai_rejected = any(
        isinstance(e, dict) and e.get("type") == "ai_review" and "LIKELY_FALSE_POSITIVE" in str(e.get("content") or e.get("data") or "")
        for e in ev_list
    )

    status = "NEEDS VALIDATION"
    finding_state = "VALIDATING"
    if has_ai_confirmed:
        status = "CONFIRMED"
        finding_state = "CONFIRMED"
    elif has_ai_rejected:
        status = "REJECTED"
        finding_state = "REJECTED"
    elif conf >= 80 and not missing:
        status = "PENDING_AI_REVIEW"
        finding_state = "VALIDATING"
    elif conf < 40 and missing:
        status = "CANDIDATE"
        finding_state = "HYPOTHESIS"

    return {
        "status": status,
        "state": finding_state,
        "confidence": conf,
        "passed": passed,
        "missing": missing,
        "rule": rule
    }
