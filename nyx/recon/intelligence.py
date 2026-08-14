"""
NYX Recon Attack Surface Scoring & Intelligence Module
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.recon.normalizer import normalize_endpoint_url
from nyx.recon.parameters import extract_parameters_from_url
from nyx.recon.api import detect_apis
from nyx.core.router import recommend_skills


def score_endpoint(url: str, technology: list[str] | None = None, parameters: list[str] | None = None) -> dict:
    url_lower = url.lower()
    score = 20
    research_areas = set()

    # Authentication surface
    if re.search(r"login|auth|signin|signup|sso|oauth|saml", url_lower):
        score += 30
        research_areas.update(["authentication", "authorization"])

    # API surface
    if re.search(r"api/|/v1/|/v2/|/graphql", url_lower):
        score += 25
        research_areas.update(["api", "authorization"])

    # File management surface
    if re.search(r"upload|avatar|file|import|export", url_lower):
        score += 25
        research_areas.update(["file_handling", "input_validation"])

    # Technology presence
    techs = technology or []
    if any(t in ("ASP.NET", "Spring Boot", "GraphQL") for t in techs):
        score += 20

    # Parameter input presence
    params = parameters or []
    if not params:
        url_params = extract_parameters_from_url(url)
        params = [p["name"] for p in url_params]

    if params:
        score += 15
        if any(p in ("id", "token", "user", "query") for p in params):
            score += 10

    priority = "HIGH" if score >= 60 else ("MEDIUM" if score >= 40 else "LOW")

    return {
        "endpoint": url,
        "risk_score": min(score, 100),
        "priority": priority,
        "research_areas": sorted(list(research_areas)) or ["general"]
    }


def run_recon_intelligence(target: str) -> dict:
    d = _get_eng_dir()
    endpoints = []
    technologies = []

    if d.exists():
        e_file = d / "endpoints.json"
        if e_file.exists():
            try:
                endpoints = json.loads(e_file.read_text(encoding="utf-8"))
            except Exception:
                endpoints = []

        t_file = d / "technologies.json"
        if t_file.exists():
            try:
                t_data = json.loads(t_file.read_text(encoding="utf-8"))
                for items in t_data.values():
                    if isinstance(items, list):
                        technologies.extend(items)
            except Exception:
                technologies = []

    if not endpoints:
        endpoints = [
            {"url": f"https://{target}/login.aspx", "priority": "HIGH"},
            {"url": f"https://{target}/graphql", "priority": "HIGH"},
            {"url": f"https://{target}/api/users", "priority": "HIGH"}
        ]

    scored = []
    for ep in endpoints:
        ep_url = ep.get("url") if isinstance(ep, dict) else str(ep)
        res = score_endpoint(ep_url, technology=technologies)
        scored.append(res)

    scored_sorted = sorted(scored, key=lambda x: x["risk_score"], reverse=True)

    return {
        "target": target,
        "assets_count": len(endpoints),
        "technologies": list(set(technologies)),
        "prioritized_endpoints": scored_sorted
    }
