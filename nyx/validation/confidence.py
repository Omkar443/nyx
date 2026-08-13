"""
NYX Validation Engine Confidence Calculator
"""
from __future__ import annotations


def calculate_confidence(rule: dict, evidence_list: list[dict], finding_meta: dict) -> tuple[int, list[str], list[str]]:
    passed_checks = []
    missing_checks = []
    score = rule.get("base_confidence", 30)

    req_ev = rule.get("required_evidence", [])
    present_types = {e.get("type") for e in evidence_list if isinstance(e, dict)}

    # Check evidence types
    for ev_req in req_ev:
        if ev_req in present_types or ("http_request" in present_types and "http_response" in present_types):
            score += 15
            passed_checks.append(f"Evidence type '{ev_req}' attached")
        else:
            missing_checks.append(f"Missing evidence type: {ev_req}")

    # Check endpoint / parameter presence
    if finding_meta.get("endpoint"):
        score += 10
        passed_checks.append("Endpoint accepts target parameter / URL path")
    else:
        missing_checks.append("Vulnerable endpoint not specified")

    if finding_meta.get("parameter"):
        score += 10
        passed_checks.append("Specific parameter identified")

    # Check checklist items
    checklist = rule.get("checklist", [])
    if len(evidence_list) >= 2:
        score += 20
        passed_checks.append("Multiple evidence artifacts attached and verified")
    elif len(evidence_list) == 1:
        score += 10
        passed_checks.append("Initial evidence artifact attached")
    else:
        missing_checks.append("No empirical evidence attached")

    final_score = min(score, 100)
    return final_score, passed_checks, missing_checks
