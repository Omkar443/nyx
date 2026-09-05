"""
NYX Analysis Application Service
Orchestrates attack surface analysis, vulnerability classification, and technology mapping.
"""
from __future__ import annotations

from typing import Any
from nyx.core import analysis as core_analysis


class AnalysisService:
    """Service facade for surface analysis and classification."""

    def classify(self, target_url: str) -> dict[str, Any]:
        return core_analysis.classify_url(url=target_url)

    def classify_url(
        self, target_url: str, burp: bool = False, proxy: str | None = None
    ) -> dict[str, Any]:
        res = core_analysis.classify_url(url=target_url)
        matches = res.get("matches", {})
        skills = list(matches.keys())
        url_lower = target_url.lower()
        cmd_indicators = (
            "cmd=", "exec=", "command=", "run=", "ping=", "host=",
            "lookup=", "dns=", "ip=", "target_host=",
            "/dns-lookup", "/command-injection", "/ping", "/traceroute",
            "/exec", "/shell", "/terminal"
        )
        has_cmd_indicator = any(k in url_lower for k in cmd_indicators)

        category = "WEB_ENDPOINT"
        if "graphql" in url_lower or any(s in ("hunt-graphql", "hunt-fintech-graphql") for s in skills):
            category = "GRAPHQL_SURFACE"
        elif any(s in ("hunt-auth-bypass", "hunt-ato", "hunt-oauth", "hunt-saml", "hunt-forgot-password", "hunt-mfa-bypass") for s in skills):
            category = "AUTH_IDENTITY_SURFACE"
        elif any(s in ("hunt-file-upload", "hunt-lfi") for s in skills):
            category = "FILE_UPLOAD_SURFACE"
        elif any(s in ("hunt-ssrf", "hunt-open-redirect") for s in skills):
            category = "REDIRECT_SSRF_SURFACE"
        elif any(s in ("hunt-sqli",) for s in skills):
            category = "SQLI_SURFACE"
        elif any(s in ("hunt-xss", "hunt-html-injection") for s in skills):
            category = "XSS_SURFACE"
        elif any(s in ("hunt-idor", "hunt-api-misconfig") for s in skills):
            category = "API_IDOR_SURFACE"
        elif ("hunt-rce" in skills and has_cmd_indicator) or has_cmd_indicator:
            category = "COMMAND_INJECTION_SURFACE"

        return {
            "status": "success",
            "url": target_url,
            "category": category,
            "skills": skills if skills else ["bb-methodology"],
            "matches": matches,
        }

    def analyze_surface(
        self, target: str, manifest: str | None = None
    ) -> dict[str, Any]:
        return core_analysis.get_surface(target=target, manifest=manifest)

    def rank_surface(
        self, target: str, manifest: str | None = None
    ) -> dict[str, Any]:
        return core_analysis.rank_surface(target=target, manifest=manifest)

    def technology_map(self, tech_name: str | None = None) -> dict[str, Any]:
        return core_analysis.get_technology_map(technology=tech_name)

    def get_decision_context(
        self, target: str | None = None, url: str | None = None, tech_stack: list[str] | None = None
    ) -> dict[str, Any]:
        return core_analysis.decision_context(
            target=target, url=url
        )
