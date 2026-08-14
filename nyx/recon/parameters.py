"""
NYX Recon Parameter Classification Intelligence Module
"""
from __future__ import annotations
import re
from urllib.parse import parse_qs, urlparse


IDENTITY_PARAMS = {"id", "user", "username", "account", "profile", "user_id", "account_id", "doc_id"}
AUTH_PARAMS = {"token", "session", "jwt", "auth", "bearer", "key", "api_key", "secret"}
INJECTION_PARAMS = {"query", "search", "filter", "sort", "order", "cmd", "exec", "url", "dest", "redirect", "file"}


def classify_parameter(param_name: str) -> dict:
    p_lower = param_name.lower().strip()
    p_type = "general"
    priority = "MEDIUM"

    if p_lower in IDENTITY_PARAMS or re.search(r"(^|_)id$|user|account", p_lower):
        p_type = "object_identifier"
        priority = "HIGH"
    elif p_lower in AUTH_PARAMS or re.search(r"token|session|jwt|key|secret", p_lower):
        p_type = "authentication"
        priority = "HIGH"
    elif p_lower in INJECTION_PARAMS or re.search(r"query|search|filter|sort|cmd|exec|url|file", p_lower):
        p_type = "injection_candidate"
        priority = "HIGH"

    return {
        "name": param_name,
        "type": p_type,
        "priority": priority
    }


def extract_parameters_from_url(url: str) -> list[dict]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    classified = []
    for p in params.keys():
        classified.append(classify_parameter(p))
    return classified
