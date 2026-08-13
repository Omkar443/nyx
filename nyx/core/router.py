"""
NYX Core Intelligent Skill Router
"""
from __future__ import annotations
import json
import re
from nyx.core.knowledge import load_knowledge, load_technology, search_knowledge


def recommend_skills(url: str, technology: str | None = None, endpoint_type: str | None = None) -> dict:
    """Intelligent Skill Router — matches URL, technology stack, and endpoint context against
    the NYX Knowledge Base to produce skill recommendations, attack surfaces, and priority."""
    url_lower = url.lower()
    recommended_skills = set()
    surfaces = set()
    priority = "MEDIUM"

    # Match technology knowledge
    if technology:
        tech_k = load_technology(technology)
        if tech_k:
            for sk in tech_k.get("related_skills", []):
                recommended_skills.add(sk)
            surf_dict = tech_k.get("attack_surface", {})
            for surf_cat, details in surf_dict.items():
                surfaces.add(surf_cat)

    # Match URL endpoint patterns
    if re.search(r"login|auth|signin|signup|sso|oauth|saml", url_lower):
        surfaces.update(["authentication", "session", "authorization"])
        recommended_skills.update(["hunt-auth-bypass", "hunt-ato", "hunt-mfa-bypass", "hunt-brute-force"])
        priority = "HIGH"
    elif re.search(r"api/|/v1/|/v2/|/graphql", url_lower):
        surfaces.update(["api", "authorization", "mass_assignment"])
        recommended_skills.update(["hunt-api-misconfig", "hunt-idor", "hunt-spa-api"])
        priority = "HIGH"
    elif re.search(r"upload|avatar|file|import|attachment", url_lower):
        surfaces.update(["file_handling", "input_validation"])
        recommended_skills.update(["hunt-file-upload", "hunt-lfi", "hunt-xxe"])
        priority = "HIGH"

    if endpoint_type:
        surfaces.add(endpoint_type.lower())

    # Knowledge search fallback for any tech/url keywords
    search_res = search_knowledge(technology=technology, keyword=endpoint_type or url)
    for sk in search_res.get("matched_skills", []):
        recommended_skills.add(sk)

    # Query Skill Library
    from nyx.core.skills import load_skills
    all_skills = load_skills()
    if technology:
        for s_name, s_info in all_skills.items():
            if any(technology.lower() in t.lower() for t in s_info.get("technology", [])):
                recommended_skills.add(s_name)

    tech_name = technology or "Unknown"
    reason = f"Endpoint '{url}' matching attack surface '{', '.join(surfaces) or 'general'}' running {tech_name}"

    return {
        "endpoint": url,
        "technology": tech_name,
        "attack_surface": sorted(list(surfaces)) or ["general"],
        "recommended_skills": sorted(list(recommended_skills)) or ["bb-methodology", "hunt-xss", "hunt-idor"],
        "priority": priority,
        "reason": reason
    }


def analyze_target_context(context_dict: dict) -> dict:
    url = context_dict.get("url", "")
    tech = context_dict.get("technology")
    ep_type = context_dict.get("endpoint_type")
    return recommend_skills(url, technology=tech, endpoint_type=ep_type)


def rank_attack_surface(target: str, endpoints: list[str] | None = None, technologies: list[str] | None = None) -> list[dict]:
    eps = endpoints or []
    techs = technologies or []
    ranked = []

    for ep in eps:
        rec = recommend_skills(ep, technology=techs[0] if techs else None)
        ranked.append({
            "endpoint": ep,
            "priority": rec.get("priority", "MEDIUM"),
            "surfaces": rec.get("attack_surface", []),
            "skills": rec.get("recommended_skills", [])
        })

    return sorted(ranked, key=lambda x: (0 if x["priority"] == "HIGH" else 1))
