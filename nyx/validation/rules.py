"""
NYX Validation Engine Rules Specification
"""
from __future__ import annotations

VALIDATION_RULES = {
    "auth_bypass": {
        "type": "Authentication Bypass",
        "category": "authentication",
        "required_evidence": ["http_request", "http_response"],
        "checklist": [
            "Unauthenticated request to protected endpoint",
            "HTTP 200/204 response returning sensitive user data or state change",
            "Missing session/Bearer token enforcement"
        ],
        "rejection_conditions": [
            "Endpoint is public by design",
            "HTTP 401/403 returned",
            "Static asset/public content only"
        ],
        "base_confidence": 30
    },
    "idor": {
        "type": "IDOR",
        "category": "authorization",
        "required_evidence": ["http_request", "http_response", "authorization_comparison"],
        "checklist": [
            "User A context requesting User B resource ID",
            "HTTP 200 response returning User B sensitive data",
            "Object identifier present in path/query/body"
        ],
        "rejection_conditions": [
            "Resource belongs to public data",
            "User B ID returns HTTP 403 or empty data",
            "User A and User B belong to same organization with shared access by design"
        ],
        "base_confidence": 35
    },
    "sqli": {
        "type": "SQL Injection",
        "category": "injection",
        "required_evidence": ["http_request", "http_response"],
        "checklist": [
            "SQL syntax probe injected into parameter",
            "Database error traceback, boolean diff, or time delay observed",
            "Parameter reflects unescaped query payload"
        ],
        "rejection_conditions": [
            "Generic 500 error without database traceback",
            "WAF block page (403)",
            "Input properly parameterized"
        ],
        "base_confidence": 40
    },
    "reflected_xss": {
        "type": "Reflected XSS",
        "category": "xss",
        "required_evidence": ["http_request", "http_response"],
        "checklist": [
            "Polyglot script probe injected into parameter",
            "Unescaped payload reflected in response body",
            "Rendered in HTML/script execution context"
        ],
        "rejection_conditions": [
            "HTML entity encoded (< -> &lt;)",
            "Content-Type is application/json or text/plain without HTML execution",
            "SameSite=Strict cookie blocks execution context"
        ],
        "base_confidence": 30
    },
    "mass_assignment": {
        "type": "Mass Assignment",
        "category": "api",
        "required_evidence": ["http_request", "http_response"],
        "checklist": [
            "Protected JSON field (is_admin, role, verified) sent in update request",
            "Server accepts request with HTTP 200",
            "Field state updated in subsequent response/get request"
        ],
        "rejection_conditions": [
            "Server ignores protected parameter",
            "HTTP 400 Bad Request returned",
            "Field requires elevated privilege to modify"
        ],
        "base_confidence": 30
    }
}


RULE_ALIASES = {
    "xss": "reflected_xss",
    "reflected_xss": "reflected_xss",
    "sql_injection": "sqli",
    "sql": "sqli",
    "authentication_bypass": "auth_bypass",
    "auth": "auth_bypass",
    "massassignment": "mass_assignment",
}


def get_rule(vuln_type: str) -> dict | None:
    v_clean = vuln_type.lower().strip().replace(" ", "_")
    target_key = RULE_ALIASES.get(v_clean, v_clean)

    for key, rule in VALIDATION_RULES.items():
        if key == target_key or key == v_clean or rule["type"].lower() == vuln_type.lower().strip():
            return rule
    return None
