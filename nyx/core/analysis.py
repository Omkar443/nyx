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

STOPWORDS = {
    # Generic protocol & web structural words
    "http", "https", "index", "default", "documentation", "document", "public",
    # Generic English structural words (4+ letters)
    "when", "from", "with", "built", "where", "that", "this", "over", "into",
    "have", "also", "used", "uses", "using", "find", "check", "info", "read",
    "only", "mode", "more", "some", "such", "than", "then", "very", "were",
    # Generic security, testing & bug bounty meta-terms
    "server", "page", "network", "access", "application", "data", "user",
    "request", "response", "attack", "security", "vulnerability", "vulnerabilities",
    "test", "testing", "hunt", "hunting", "target", "targets", "skill",
    "bounty", "chain", "reports", "system", "specific",
}

URL_PATTERN_TO_SKILLS = [
    (r"[?&](url|next|redirect|return|callback|target|destination|continue)=", ["hunt-ssrf", "hunt-open-redirect"]),
    (r"[?&](id|user|userid|user_id|uid|pid|post|order|invoice|account|report_id)=\d", ["hunt-idor"]),
    (r"/(api|rest|v[0-9])/", ["hunt-api-misconfig", "hunt-idor"]),
    (r"/(payment|wallet|fintech|checkout|billing).*/graphql|/graphql.*[?&](mutation|op)=(transfer|pay|refund|withdraw)", ["hunt-fintech-graphql", "hunt-graphql"]),
    (r"/graphql", ["hunt-graphql"]),
    (r"/(login|signin|signup|register|forgot|reset|auth|password|account-recovery)", ["hunt-auth-bypass", "hunt-ato", "hunt-api-misconfig", "hunt-forgot-password", "hunt-jwt-crypto"]),
    (r"/oauth/(authorize|token|callback)", ["hunt-oauth", "hunt-ato"]),
    (r"/saml/(acs|sso|metadata)", ["hunt-saml"]),
    (r"/_layouts/15/|/_vti_bin/|/_api/(web|contextinfo)", ["hunt-sharepoint"]),
    (r"/(file|upload|attachment|avatar|document|media|picture|pictures|photo|photos|image|images|video|videos|arbitrary-file-inclusion|file-upload)", ["hunt-file-upload", "hunt-lfi", "hunt-ssrf"]),
    (r"/(convert|transform|render|transcode|pdf|webhook|callback)", ["hunt-ssrf", "hunt-file-upload"]),
    (r"/(contact|merchant|mechanic|message|support|ticket|notify)", ["hunt-brute-force", "hunt-race-condition", "hunt-business-logic", "hunt-ssrf"]),
    (r"[?&](cmd|exec|command|run|ping|host|lookup|dns|ip|target_host|domain|address)=|/(dns-lookup|command-injection|ping|traceroute|exec|shell|terminal)", ["hunt-rce"]),
    (r"[?&](username|user|user_id|uid|id|password|pass|email|name|search|query|q|cat|category|item|sort|order_by|select|account|number|author|blog_entry)=|/(user-info|view-someones-blog|show-log|sql|database)", ["hunt-sqli"]),
    (r"[?&](content|body|text|title|description|blog|message|msg|comment|feedback|heading|note|input|author)=|/(add-to-your-blog|view-someones-blog|html5-storage|javascript|xss)", ["hunt-xss", "hunt-html-injection"]),
    (r"/search\?", ["hunt-xss", "hunt-sqli"]),
    (r"[?&]q=|[?&]query=|[?&]s=", ["hunt-xss"]),
    (r"\.(php|aspx?|cgi|jsp)", ["hunt-rce", "hunt-aspnet"]),
    (r"/(admin|management|debug|test|staging|dev|internal|actuator|health)", ["hunt-auth-bypass", "hunt-api-misconfig", "hunt-idor"]),
    (r"/jenkins|jnlpJars|/cli", ["hunt-rce"]),
    (r"/functionRouter|/uppercase|/lowercase", ["hunt-rce", "hunt-ssti"]),
    (r"/(2fa|mfa|otp|verify|check-otp)", ["hunt-mfa-bypass", "hunt-brute-force"]),
    (r"/(coupon|promo|cart|checkout|order|orders|return_order|refund)", ["hunt-business-logic", "hunt-race-condition", "hunt-nosqli", "hunt-api-misconfig"]),
    (r"/(comment|review|feedback|forum|post|posts)", ["hunt-xss", "hunt-html-injection", "hunt-business-logic", "hunt-idor"]),
    (r"/(jwt|jwks|\.well-known/jwks)", ["hunt-jwt-crypto", "hunt-source-leak"]),
    (r"/(chat|chatbot|assistant|prompt|llm)", ["hunt-rag-vector", "hunt-api-misconfig"]),
    (r"/parse-xml|/import-xml|\.xml", ["hunt-xxe"]),
]


def extract_router_targets(url: str) -> list[str]:
    """
    Extract literal URL, parsed path, and any router parameter values (e.g. ?page=user-info.php, ?action=login)
    to support router-aware classification for PHP front-controllers, query routers, and SPA routes.
    """
    targets: list[str] = []
    clean_url = (url or "").strip()
    if not clean_url:
        return targets
    targets.append(clean_url)

    parsed = urllib.parse.urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
    if parsed.path:
        targets.append(parsed.path)
    if parsed.fragment:
        frag_path = parsed.fragment.split("?")[0].strip()
        if frag_path:
            if not frag_path.startswith("/"):
                frag_path = f"/{frag_path}"
            if len(frag_path) > 1:
                targets.append(frag_path)

    qs = {}
    if parsed.query:
        qs.update(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
    if parsed.fragment and "?" in parsed.fragment:
        qs.update(urllib.parse.parse_qs(parsed.fragment.split("?", 1)[1], keep_blank_values=True))

    if qs:
        router_param_names = {
            "page", "action", "view", "module", "p", "tab", "file", "target", "path",
            "include", "component", "route", "sec", "section", "cmd", "func", "function", "do",
        }
        for k, v_list in qs.items():
            k_lower = k.lower()
            for v in v_list:
                v_clean = str(v).strip()
                if not v_clean:
                    continue
                if k_lower in router_param_names or any(
                    v_clean.lower().endswith(ext)
                    for ext in [".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".html", ".htm"]
                ):
                    targets.append(f"/{v_clean.lstrip('/')}")
                    targets.append(f"{k_lower}={v_clean}")
    return list(dict.fromkeys(targets))

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
    "graphql": ["hunt-graphql", "hunt-fintech-graphql", "hunt-idor", "hunt-brute-force"],
    "fintech": ["hunt-fintech-graphql", "hunt-business-logic", "hunt-race-condition"],
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
    target_segments = extract_router_targets(url)

    for pattern, skill_names in URL_PATTERN_TO_SKILLS:
        for seg in target_segments:
            if re.search(pattern, seg, re.I):
                for s in skill_names:
                    matches.setdefault(s, []).append(f"Target matches /{pattern}/")

    all_text = " ".join(target_segments).lower()
    keywords = [kw for kw in re.findall(r"[a-z]{4,}", all_text) if kw not in STOPWORDS]
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


def score_endpoint(ep_str: str) -> tuple[int, str]:
    """Score an endpoint string based on attack surface priority rules.
    Returns (score, reason).
    """
    ep_lower = ep_str.lower()
    parsed = urllib.parse.urlparse(ep_lower)
    path = parsed.path or ep_lower
    query = parsed.query

    # Low priority checks
    static_exts = (
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf"
    )
    if any(path.endswith(ext) for ext in static_exts):
        return 10, "Static asset (low attack surface priority)"

    # High priority checks
    reasons = []
    score = 50

    # API endpoints (/api/, /graphql, /v1/, /rest/)
    if re.search(r"/(api|rest|v[0-9]+|graphql)(/|\?|$)", path) or "graphql" in ep_lower:
        score += 35
        reasons.append("API / GraphQL endpoint")

    # Authentication paths (/login, /auth, /oauth, /sso)
    if re.search(r"/(login|signin|signup|auth|oauth|sso|saml|forgot|reset)(/|\?|$)", path):
        score += 35
        reasons.append("Authentication / Identity management flow")

    # Admin panels
    if re.search(r"/(admin|management|dashboard|console|internal|debug|staging|dev)(/|\?|$)", path):
        score += 35
        reasons.append("Admin / Management portal")

    # File upload functionality
    if re.search(r"/(upload|avatar|file|attachment|import|document|media)(/|\?|$)", path):
        score += 30
        reasons.append("File upload / document processing endpoint")

    # Parameters with user-controlled input
    if query or "?" in ep_str:
        score += 15
        reasons.append("User-controlled query parameters present")

    if score > 50:
        return min(score, 100), "; ".join(reasons)

    # Medium priority checks
    if re.search(r"\.(php|aspx?|jsp|cgi)$", path):
        return 45, "Dynamic server-side script endpoint"

    if any(segment in path for segment in ["/app/", "/dashboard/", "/user/", "/profile/", "/account/", "/checkout/", "/cart/"]):
        return 40, "Interactive user route / SPA path"

    return 30, "Standard web route"


def rank_surface(target: str, manifest: str | Path | None = None) -> dict[str, Any]:
    """Rank discovered endpoints for a target based on attack surface analysis."""
    surf_res = get_surface(target, manifest)
    if surf_res.get("status") == "error":
        return surf_res

    m = surf_res.get("manifest", {})
    endpoints = []

    # Gather endpoints from manifest
    if "endpoints" in m and isinstance(m["endpoints"], list):
        endpoints.extend(m["endpoints"])

    if "hosts" in m and isinstance(m["hosts"], list):
        for h in m["hosts"]:
            url = h.get("url") if isinstance(h, dict) else str(h)
            if url and url not in endpoints:
                endpoints.append(url)

    if "subdomains" in m and isinstance(m["subdomains"], list):
        for sub in m["subdomains"]:
            url = f"https://{sub}"
            if url not in endpoints:
                endpoints.append(url)

    has_manifest_keys = any(k in m for k in ("endpoints", "hosts", "subdomains"))
    # Only check engagement memory if manifest didn't explicitly specify endpoint lists
    if not endpoints and not has_manifest_keys:
        d = _get_eng_dir()
        if d.exists():
            e_file = d / "endpoints.json"
            if e_file.exists():
                try:
                    from nyx.ai.context import _matches_target_endpoint

                    def _is_ep_for_target(ep_url: str, tgt: str) -> bool:
                        if not ep_url or not tgt:
                            return False
                        if ep_url.startswith("/") or ep_url.startswith("?"):
                            return True
                        return _matches_target_endpoint(ep_url, tgt)

                    e_data = json.loads(e_file.read_text(encoding="utf-8"))
                    for item in e_data:
                        u = item.get("url") if isinstance(item, dict) else str(item)
                        if u and _is_ep_for_target(u, target) and u not in endpoints:
                            endpoints.append(u)
                except Exception:
                    pass

    rankings = []
    seen = set()
    for ep in endpoints:
        ep_str = ep.get("url") if isinstance(ep, dict) else str(ep)
        if not ep_str or ep_str in seen:
            continue
        seen.add(ep_str)
        score, reason = score_endpoint(ep_str)
        rankings.append({
            "endpoint": ep_str,
            "score": score,
            "reason": reason,
        })

    # Sort descending by score
    rankings.sort(key=lambda x: x["score"], reverse=True)

    return {
        "status": "success",
        "target": target,
        "manifest_path": surf_res.get("manifest_path"),
        "rankings": rankings,
    }


def get_surface(
    target: str, manifest: str | Path | None = None
) -> dict[str, Any]:
    mpath = Path(manifest) if manifest else None
    target_clean = re.sub(r"^https?://", "", target).rstrip("/")
    target_folder = re.sub(r'[:/\\?*|"<>]', '_', target_clean)

    if not mpath:
        for base in (REPO_ROOT / "recon", Path.cwd() / "recon"):
            for cand_name in (target, target_clean, target_folder):
                cand = base / cand_name / "manifest.json"
                if cand.exists():
                    mpath = cand
                    break
            if mpath:
                break

    if not mpath or not mpath.exists():
        if manifest is None:
            d = _get_eng_dir()
            if d.exists() and (d / "endpoints.json").exists():
                try:
                    from nyx.ai.context import _matches_target_endpoint

                    def _is_ep_for_target(ep_url: str, tgt: str) -> bool:
                        if not ep_url or not tgt:
                            return False
                        if ep_url.startswith("/") or ep_url.startswith("?"):
                            return True
                        return _matches_target_endpoint(ep_url, tgt)

                    eps = json.loads((d / "endpoints.json").read_text(encoding="utf-8"))
                    target_eps = [
                        e.get("url") if isinstance(e, dict) else str(e)
                        for e in eps
                        if _is_ep_for_target(e.get("url") if isinstance(e, dict) else str(e), target)
                    ]
                    if target_eps:
                        return {
                            "status": "success",
                            "target": target,
                            "manifest_path": str(d / "endpoints.json"),
                            "manifest": {"endpoints": target_eps}
                        }
                except Exception:
                    pass
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
        
        raw_text = tf.read_text(encoding="utf-8")
        import yaml
        try:
            data = yaml.safe_load(raw_text) or {}
        except Exception:
            data = {}

        tech_name = data.get("technology", technology)
        category = "API" if technology.lower() in ("graphql", "grpc", "rest") else "Framework / Infrastructure"
        
        attack_surface = data.get("attack_surface", [])
        vulnerabilities = data.get("vulnerabilities", [])
        skills_to_load = data.get("skills_to_load", [])
        
        vectors = []
        for surf in attack_surface:
            vectors.append({"name": str(surf), "description": f"{tech_name} attack vector on {surf}"})
        for vuln in vulnerabilities:
            vectors.append({"name": str(vuln), "description": f"Potential {vuln} in {tech_name}"})

        return {
            "status": "success",
            "technology": tech_name,
            "category": category,
            "path": str(tf),
            "vectors": vectors,
            "recommended_skills": skills_to_load,
            "content": raw_text,
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
        "endpoint": ep,
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
