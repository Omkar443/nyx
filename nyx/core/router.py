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

    # 1. Registration & User Creation Surface
    if re.search(r"register|signup|registration|user/create|user/new|account/create|adduser|/users?(/|$|\?)", url_lower):
        surfaces.update(["registration", "authentication", "mass_assignment", "input_validation"])
        recommended_skills.update(["hunt-api-misconfig", "hunt-exceptional-conditions", "hunt-auth-bypass"])
        priority = "HIGH"
    elif re.search(r"login|auth|signin|sso|oauth|saml|reset-password|forgot-password|password|otp|mfa|session|verify-token|check-otp", url_lower):
        surfaces.update(["authentication", "session", "authorization"])
        recommended_skills.update(["hunt-auth-bypass", "hunt-ato", "hunt-mfa-bypass", "hunt-brute-force", "hunt-forgot-password", "hunt-jwt-crypto"])
        priority = "HIGH"

    # 2. Business Logic / Cart / Pricing / Orders / Coupons / Feedback Surface
    if re.search(r"basket|cart|checkout|order|pay|payment|billing|wallet|membership|deluxe|subscription|coupon|discount|voucher|promo|redeem|quantity|price|amount|rating|stars|feedback|review|comment|vote|score", url_lower):
        surfaces.update(["business_logic", "financial_tampering", "input_validation"])
        recommended_skills.update(["hunt-business-logic", "hunt-exceptional-conditions", "hunt-race-condition", "hunt-nosqli"])
        priority = "HIGH"

    # 3. File Upload / Pictures / Videos / Media Processing Surface
    if re.search(r"upload|avatar|picture|pictures|photo|photos|image|images|video|videos|attachment|file/new|import|export|media|document|archive|zipslip|multipart", url_lower):
        surfaces.update(["file_handling", "input_validation", "path_traversal"])
        recommended_skills.update(["hunt-file-upload", "hunt-lfi", "hunt-ssrf", "hunt-xxe"])
        priority = "HIGH"

    # 4. Conversion, Rendering, Webhooks & SSRF Surface
    if re.search(r"convert|transform|render|transcode|pdf|webhook|callback|fetch|preview", url_lower):
        surfaces.update(["ssrf", "media_processing", "input_validation"])
        recommended_skills.update(["hunt-ssrf", "hunt-file-upload", "hunt-business-logic"])
        priority = "HIGH"

    # 5. Contact, Dispatch, Messaging & Rate Limiting Surface
    if re.search(r"contact|merchant|mechanic|message|support|ticket|notify|notification|email/send|resend", url_lower):
        surfaces.update(["rate_limiting", "communication", "business_logic"])
        recommended_skills.update(["hunt-brute-force", "hunt-race-condition", "hunt-business-logic", "hunt-ssrf"])
        priority = "HIGH"

    # 6. Path / File Serving / Download / Static / FTP Surface
    if re.search(r"ftp/|files?/|downloads?/|static/|view|read|report|doc(s)?/|path=|file=|filename=|doc=|template=|include=|page=|load=|dir=|src=", url_lower):
        surfaces.update(["file_serving", "path_traversal", "information_disclosure"])
        recommended_skills.update(["hunt-lfi", "hunt-source-leak", "hunt-exceptional-conditions", "hunt-idor"])
        priority = "HIGH"

    # 7. JWT / Token & Session Surface
    if re.search(r"jwt|token|bearer|jwks|keystore|\.well-known/jwks\.json", url_lower):
        surfaces.update(["cryptography", "jwt", "session"])
        recommended_skills.update(["hunt-jwt-crypto", "hunt-auth-bypass", "hunt-session", "hunt-source-leak"])
        priority = "HIGH"

    # 8. Admin / Management / Monitoring Surface
    if re.search(r"admin|management|dashboard|console|actuator|health|metrics|status|internal|debug|staging|dev", url_lower):
        surfaces.update(["admin", "management", "authorization"])
        recommended_skills.update(["hunt-auth-bypass", "hunt-api-misconfig", "hunt-idor"])
        priority = "HIGH"

    # 9. LLM / AI / Chatbot Surface
    if re.search(r"chat|chatbot|assistant|prompt|completion|llm|ai/", url_lower):
        surfaces.update(["llm_ai", "vector_rag"])
        recommended_skills.update(["hunt-rag-vector", "hunt-api-misconfig", "hunt-dom"])
        priority = "HIGH"

    # 10. Well-Known Metadata & Security Policy Surface
    if re.search(r"\.well-known/security\.txt|security\.txt|robots\.txt|sitemap\.xml|crossdomain\.xml|\.sigma", url_lower):
        surfaces.update(["metadata", "information_disclosure"])
        recommended_skills.update(["hunt-source-leak", "offensive-osint", "hunt-tls-network"])
        priority = "LOW" if priority != "HIGH" else priority

    # 11. General API & GraphQL Surface
    if re.search(r"api/|/v1/|/v2/|/graphql", url_lower):
        surfaces.update(["api", "authorization"])
        recommended_skills.update(["hunt-api-misconfig", "hunt-idor", "hunt-spa-api"])
        priority = "HIGH"

    # Technology & Infrastructure Surface Mapping
    if technology:
        t_low = technology.lower()
        if any(k in t_low for k in ("node", "express", "fastify", "nest")):
            recommended_skills.add("hunt-nodejs")
        if any(k in t_low for k in ("spring", "java")):
            recommended_skills.add("hunt-springboot")
        if any(k in t_low for k in ("asp.net", "iis", "c#", ".net")):
            recommended_skills.add("hunt-aspnet")
        if any(k in t_low for k in ("laravel", "php", "symfony")):
            recommended_skills.add("hunt-laravel")
        if any(k in t_low for k in ("k8s", "kubernetes", "docker")):
            recommended_skills.add("hunt-k8s")
        if any(k in t_low for k in ("next", "react")):
            recommended_skills.add("hunt-nextjs")

    if endpoint_type:
        surfaces.add(endpoint_type.lower())

    # Knowledge search fallback for any tech/url keywords
    search_res = search_knowledge(technology=technology, keyword=endpoint_type or url)
    for sk in search_res.get("matched_skills", []):
        recommended_skills.add(sk)

    # Query Skill Library
    if technology:
        from nyx.core.skills import load_skills
        all_skills = load_skills()
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
