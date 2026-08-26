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
    },
    "graphql": {
        "type": "GraphQL Access Control & Business Logic",
        "category": "api",
        "required_evidence": ["http_request", "http_response"],
        "checklist": [
            "GraphQL query or mutation payload executed",
            "Schema node ID or financial mutation accessed without proper authorization",
            "HTTP 200 response with data payload returning cross-tenant or protected records"
        ],
        "rejection_conditions": [
            "GraphQL errors array contains unauthorized/forbidden message",
            "Introspection disabled and field rejected",
            "Public query data only"
        ],
        "base_confidence": 35
    },
    "ssrf": {
        "type": "Server-Side Request Forgery",
        "category": "ssrf",
        "required_evidence": ["http_request", "http_response", "oob_interaction"],
        "checklist": [
            "Internal IP, cloud metadata URL, or OOB collaborator URL injected",
            "Backend server performs fetch and reflects internal content or triggers DNS/HTTP callback",
            "Cloud instance credentials or internal service banner retrieved"
        ],
        "rejection_conditions": [
            "Client-side fetch only (no server-side interaction)",
            "DNS lookup without HTTP request and no internal reach",
            "WAF blocks external/internal target IP"
        ],
        "base_confidence": 40
    },
    "cache_poison": {
        "type": "Web Cache Deception / Poisoning",
        "category": "cache",
        "required_evidence": ["http_request", "http_response"],
        "checklist": [
            "Unkeyed header or path-normalization crafted request sent",
            "Response reflects injected header or victim sensitive profile",
            "Subsequent unauthenticated GET request from second client receives cached poisoned response"
        ],
        "rejection_conditions": [
            "Cache-Control: no-store or private header present",
            "Second request returns cache MISS and unpoisoned content",
            "Dynamic response never cached by edge CDN"
        ],
        "base_confidence": 35
    },
    "race_condition": {
        "type": "Race Condition / Concurrency Double-Spend",
        "category": "business_logic",
        "required_evidence": ["http_request", "http_response", "concurrency_trace"],
        "checklist": [
            "Concurrent or single-packet synchronization requests sent within race window",
            "Multiple state-changing operations succeed against a single-use token, coupon, or balance",
            "Ledger or account state shows duplicate redemption"
        ],
        "rejection_conditions": [
            "Database transactional locks enforce serial execution (409 Conflict / 400)",
            "Only one request succeeds and all others return failure",
            "Rate limiter blocks concurrent requests"
        ],
        "base_confidence": 40
    }
}


RULE_ALIASES = {
    "xss": "reflected_xss",
    "reflected_xss": "reflected_xss",
    "cross-site_scripting": "reflected_xss",
    "cross_site_scripting": "reflected_xss",
    "sql_injection": "sqli",
    "sql": "sqli",
    "sqli": "sqli",
    "authentication_bypass": "auth_bypass",
    "auth": "auth_bypass",
    "auth_bypass": "auth_bypass",
    "massassignment": "mass_assignment",
    "mass_assignment": "mass_assignment",
    "idor": "idor",
    "insecure_direct_object_reference": "idor",
    "graphql": "graphql",
    "fintech_graphql": "graphql",
    "ssrf": "ssrf",
    "server-side_request_forgery": "ssrf",
    "server_side_request_forgery": "ssrf",
    "cache_poison": "cache_poison",
    "web_cache_deception": "cache_poison",
    "cache_deception": "cache_poison",
    "race_condition": "race_condition",
    "race": "race_condition",
    "concurrency": "race_condition",
}


def get_rule(vuln_type: str) -> dict | None:
    v_clean = vuln_type.lower().strip().replace(" ", "_").replace("-", "_")
    target_key = RULE_ALIASES.get(v_clean, v_clean)

    for key, rule in VALIDATION_RULES.items():
        if key == target_key or key == v_clean or rule["type"].lower() == vuln_type.lower().strip():
            return rule
    return None
