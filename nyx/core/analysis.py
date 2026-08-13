"""
NYX Core Surface Analysis & Decision Context Engine
Canonical business logic for URL classification, surface analysis, technology mapping, and decision context generation.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

from nyx.infrastructure.filesystem import REPO_ROOT, _get_eng_dir
from nyx.infrastructure.urls import normalize_url

SKILL_DESC_CACHE: dict[str, str] = {}
SKILLS_DIR = REPO_ROOT / "skills"
REPORTS_DIR = REPO_ROOT / "docs" / "disclosed-reports"

URL_PATTERN_TO_SKILLS = [
    (r"[?&](url|next|redirect|return|callback|target|destination|continue)=", ["hunt-ssrf"]),
    (r"[?&](id|user|userid|user_id|uid|pid|post|order|invoice|account)=\d", ["hunt-idor"]),
    (r"/(api|rest|v[0-9])/", ["hunt-api-misconfig", "hunt-idor"]),
    (r"/graphql", ["hunt-graphql"]),
    (r"/(login|signin|signup|register|forgot|reset)", ["hunt-auth-bypass", "hunt-ato"]),
    (r"/oauth/(authorize|token|callback)", ["hunt-oauth"]),
    (r"/saml/(acs|sso|metadata)", ["hunt-saml"]),
    (r"/_layouts/15/|/_vti_bin/|/_api/(web|contextinfo)", ["hunt-sharepoint"]),
    (r"/(file|upload|attachment|avatar|document|media)", ["hunt-file-upload"]),
    (r"/search\?", ["hunt-xss", "hunt-sqli"]),
    (r"[?&]q=|[?&]query=|[?&]s=", ["hunt-xss"]),
    (r"\.(php|aspx?|cgi|jsp)", ["hunt-rce", "hunt-aspnet"]),
    (r"/(admin|management|debug|test|staging|dev|internal)", ["hunt-auth-bypass"]),
    (r"/jenkins|jnlpJars|/cli", ["hunt-rce"]),
    (r"/functionRouter|/uppercase|/lowercase", ["hunt-rce", "hunt-ssti"]),
    (r"/(2fa|mfa|otp|verify)", ["hunt-mfa-bypass"]),
    (r"/(coupon|promo|cart|checkout)", ["hunt-business-logic", "hunt-race-condition"]),
    (r"/(webhook|callback/event)", ["hunt-business-logic"]),
    (r"/parse-xml|/import-xml|\.xml", ["hunt-xxe"]),
]

TECHNOLOGY_SKILL_MAP = {
    "asp.net": ["hunt-aspnet", "hunt-auth-bypass", "hunt-ato"],
    "aspnet": ["hunt-aspnet", "hunt-auth-bypass", "hunt-ato"],
    "laravel": ["hunt-laravel", "hunt-rce", "hunt-source-leak"],
    "spring": ["hunt-springboot", "hunt-rce", "hunt-ssti"],
    "springboot": ["hunt-springboot", "hunt-rce", "hunt-ssti"],
    "next.js": ["hunt-nextjs", "hunt-ssrf", "hunt-spa-api"],
    "nextjs": ["hunt-nextjs", "hunt-ssrf", "hunt-spa-api"],
    "node.js": ["hunt-nodejs", "hunt-rce", "hunt-dom"],
    "nodejs": ["hunt-nodejs", "hunt-rce", "hunt-dom"],
    "express": ["hunt-nodejs", "hunt-api-misconfig"],
    "graphql": ["hunt-graphql", "hunt-idor", "hunt-brute-force"],
    "grpc": ["hunt-grpc", "hunt-api-misconfig"],
    "sharepoint": ["hunt-sharepoint", "hunt-aspnet", "hunt-ntlm-info"],
    "vcenter": ["hunt-vmware-vcenter-attack", "hunt-rce"],
    "vpn": ["enterprise-vpn-attack", "hunt-auth-bypass"],
    "kubernetes": ["hunt-k8s", "cloud-iam-deep"],
    "k8s": ["hunt-k8s", "cloud-iam-deep"],
    "aws": ["hunt-cloud-misconfig", "cloud-iam-deep", "hunt-ssrf"],
    "gcp": ["hunt-cloud-misconfig", "cloud-iam-deep"],
    "azure": ["hunt-cloud-misconfig", "m365-entra-attack", "cloud-iam-deep"],
    "entra": ["m365-entra-attack", "hunt-auth-bypass"],
    "okta": ["okta-attack", "hunt-auth-bypass"],
    "saml": ["hunt-saml", "hunt-auth-bypass"],
    "oauth": ["hunt-oauth", "hunt-open-redirect", "hunt-ato"],
    "jwt": ["hunt-jwt-crypto", "hunt-api-misconfig"],
}

URL_PATTERN_MAP = {
    r"login|auth|signin|sso|oauth|saml": [
        "hunt-auth-bypass",
        "hunt-ato",
        "hunt-mfa-bypass",
        "hunt-brute-force",
    ],
    r"reset|forgot|password": [
        "hunt-forgot-password",
        "hunt-host-header",
        "hunt-ato",
    ],
    r"api/|/v1/|/v2/|/graphql": [
        "hunt-api-misconfig",
        "hunt-idor",
        "hunt-graphql",
        "hunt-spa-api",
    ],
    r"upload|avatar|file|import|attachment": [
        "hunt-file-upload",
        "hunt-lfi",
        "hunt-xxe",
    ],
    r"redirect|next=|url=|dest=|target=": ["hunt-open-redirect", "hunt-ssrf"],
    r"admin|dashboard|console|manage": [
        "hunt-auth-bypass",
        "hunt-idor",
        "hunt-spa-api",
    ],
}


def load_skill_descriptions() -> dict[str, str]:
    if SKILL_DESC_CACHE:
        return SKILL_DESC_CACHE
    if SKILLS_DIR.exists():
        for skill_dir in SKILLS_DIR.iterdir():
            if not skill_dir.is_dir():
                continue
            sm = skill_dir / "SKILL.md"
            if not sm.exists():
                continue
            try:
                text = sm.read_text(encoding="utf-8")
            except Exception:
                continue
            m = re.search(
                r"^description:\s*(.+?)(?=\n[a-z_]+:|^---|\Z)",
                text,
                re.M | re.S,
            )
            if m:
                desc = m.group(1).strip().strip('"').strip("'").strip()
                SKILL_DESC_CACHE[skill_dir.name] = desc[:2000]
    return SKILL_DESC_CACHE


def classify_url(url: str) -> dict[str, Any]:
    skills = load_skill_descriptions()
    matches: dict[str, list[str]] = {}
    raw = url

    for pattern, skill_names in URL_PATTERN_TO_SKILLS:
        if re.search(pattern, raw, re.I):
            for s in skill_names:
                matches.setdefault(s, []).append(f"URL matches /{pattern}/")

    keywords = re.findall(r"[a-z]{4,}", raw.lower())
    for skill, desc in skills.items():
        if skill in matches:
            continue
        score = 0
        hits = []
        for kw in set(keywords):
            if re.search(rf"\b{re.escape(kw)}\b", desc.lower()):
                score += 1
                hits.append(kw)
                if score >= 2:
                    break
        if score >= 2:
            matches[skill] = [f"description keywords: {hits}"]

    avail_reports = (
        [p.name for p in REPORTS_DIR.glob("hunt-*.md")]
        if REPORTS_DIR.exists()
        else []
    )

    return {
        "status": "success",
        "url": url,
        "matches": matches,
        "available_reports": avail_reports,
    }


def get_surface(
    target: str, manifest: str | Path | None = None
) -> dict[str, Any]:
    mpath = Path(manifest) if manifest else None
    if not mpath:
        for base in (REPO_ROOT / "recon", Path.cwd() / "recon"):
            cand = base / target / "manifest.json"
            if cand.exists():
                mpath = cand
                break

    if not mpath or not mpath.exists():
        return {
            "status": "error",
            "message": f"No recon manifest for '{target}'. Run 'nyx recon {target}' first.",
        }

    try:
        m = json.loads(mpath.read_text(encoding="utf-8"))
    except Exception as e:
        return {
            "status": "error",
            "message": f"Could not parse recon manifest at {mpath}: {e}",
        }

    return {"status": "success", "target": target, "manifest_path": str(mpath), "manifest": m}


def get_technology_map(technology: str | None = None) -> dict[str, Any]:
    maps_dir = REPO_ROOT / "skills" / "mappings" / "technologies"
    if technology:
        tf = maps_dir / f"{technology.lower()}.yaml"
        if not tf.exists():
            avail = (
                [p.stem for p in maps_dir.glob("*.yaml")]
                if maps_dir.exists()
                else []
            )
            return {
                "status": "error",
                "message": f"No technology mapping found for: {technology}",
                "available": avail,
            }
        return {
            "status": "success",
            "technology": technology,
            "path": str(tf),
            "content": tf.read_text(encoding="utf-8"),
        }
    else:
        avail_paths = list(maps_dir.glob("*.yaml")) if maps_dir.exists() else []
        avail_items = [
            {"name": p.stem.upper(), "path": str(p)} for p in avail_paths
        ]
        return {
            "status": "success",
            "technology": None,
            "mappings": avail_items,
        }


def get_decision_context(
    url: str, tech_stack: list[str] | None = None, headers: dict | None = None
) -> dict[str, Any]:
    recommended_skills = set()
    detected_tech = list(tech_stack) if tech_stack else []

    d = _get_eng_dir()
    if d.exists():
        t_file = d / "technologies.json"
        if t_file.exists():
            try:
                t_data = json.loads(t_file.read_text(encoding="utf-8"))
                for cat, items in t_data.items():
                    if isinstance(items, list):
                        detected_tech.extend(items)
            except Exception:
                pass

    url_lower = url.lower()
    for tech in set(detected_tech):
        t_clean = tech.lower()
        if t_clean in TECHNOLOGY_SKILL_MAP:
            recommended_skills.update(TECHNOLOGY_SKILL_MAP[t_clean])

    for pat, skills in URL_PATTERN_MAP.items():
        if re.search(pat, url_lower):
            recommended_skills.update(skills)

    surface_type = "general"
    if any(k in url_lower for k in ("login", "auth", "oauth", "sso")):
        surface_type = "authentication"
    elif any(k in url_lower for k in ("api", "graphql", "v1", "v2", "json")):
        surface_type = "api_endpoint"
    elif any(k in url_lower for k in ("upload", "file", "import")):
        surface_type = "file_handling"

    return {
        "status": "success",
        "url": url,
        "surface": surface_type,
        "detected_technologies": list(set(detected_tech)),
        "recommended_skills": sorted(list(recommended_skills))
        or ["bb-methodology", "hunt-xss", "hunt-idor"],
    }


def decision_context(
    target: str | None = None, url: str | None = None
) -> dict[str, Any]:
    from nyx.core.router import recommend_skills
    from nyx.core.surface import build_attack_surface_graph

    d = _get_eng_dir()
    target_name = target or "Unknown Target"
    if not target and d.exists():
        t_file = d / "target.yaml"
        if t_file.exists():
            for line in t_file.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("domain:") or line.strip().startswith(
                    "name:"
                ):
                    target_name = (
                        line.split(":", 1)[1].strip().strip('"').strip("'")
                    )
                    break

    techs = []
    if d.exists():
        tech_file = d / "technologies.json"
        if tech_file.exists():
            try:
                t_data = json.loads(tech_file.read_text(encoding="utf-8"))
                for cat, items in t_data.items():
                    if isinstance(items, list):
                        techs.extend(items)
            except Exception:
                pass

    ep = url or f"https://{target_name}/login.aspx"
    rec = recommend_skills(ep, technology=techs[0] if techs else None)
    graph = build_attack_surface_graph(target_name)

    return {
        "status": "success",
        "target": target_name,
        "technologies": list(set(techs)),
        "surface": rec.get("attack_surface"),
        "recommended_skills": rec.get("recommended_skills"),
        "graph": graph,
    }


def classify(url: str, proxy: str | None = None, burp: bool = False) -> int:
    res = classify_url(url)
    return 0 if res.get("matches") else 1


def surface(target: str, manifest: str | Path | None = None) -> int:
    res = get_surface(target, manifest)
    return 0 if res.get("status") == "success" else 1


def technology_map(technology: str | None = None) -> int:
    res = get_technology_map(technology)
    return 0 if res.get("status") == "success" else 1
