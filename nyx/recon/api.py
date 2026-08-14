"""
NYX Recon API Discovery & Fingerprinting Engine
"""
from __future__ import annotations
import re


def detect_apis(url_or_endpoints: str | list[str]) -> list[dict]:
    eps = [url_or_endpoints] if isinstance(url_or_endpoints, str) else url_or_endpoints
    detected = []

    for ep in eps:
        ep_lower = ep.lower()
        if "graphql" in ep_lower:
            detected.append({
                "type": "graphql",
                "endpoint": ep,
                "confidence": 0.95
            })
        elif any(k in ep_lower for k in ("swagger", "openapi", "api-docs")):
            detected.append({
                "type": "openapi_swagger",
                "endpoint": ep,
                "confidence": 0.90
            })
        elif re.search(r"/api/|/v1/|/v2/|/v3/", ep_lower):
            detected.append({
                "type": "rest_api",
                "endpoint": ep,
                "confidence": 0.85
            })

    return detected
