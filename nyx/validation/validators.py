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

    status = "NEEDS VALIDATION"
    finding_state = "VALIDATING"
    if conf >= 80 and not missing:
        status = "CONFIRMED"
        finding_state = "CONFIRMED"
    elif conf < 40 and missing:
        status = "CANDIDATE"
        finding_state = "VALIDATING"

    return {
        "status": status,
        "state": finding_state,
        "confidence": conf,
        "passed": passed,
        "missing": missing,
        "rule": rule
    }
