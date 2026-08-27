"""
NYX Recon Technology Fingerprinting Module
"""
from __future__ import annotations
import json
from pathlib import Path
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.core.knowledge import load_technology


HEADER_FINGERPRINTS = {
    "x-powered-by": {
        "ASP.NET": "ASP.NET",
        "Express": "Express",
        "PHP": "PHP",
        "Next.js": "Next.js",
        "Sails": "Sails.js",
        "Rails": "Ruby on Rails"
    },
    "server": {
        "Microsoft-IIS": "IIS",
        "IIS": "IIS",
        "nginx": "nginx",
        "Apache": "Apache",
        "cloudflare": "Cloudflare",
        "cloudfront": "CloudFront",
        "litespeed": "LiteSpeed",
        "kestrel": "Kestrel",
        "caddy": "Caddy",
        "gunicorn": "Gunicorn",
        "uvicorn": "Uvicorn",
        "openresty": "OpenResty"
    }
}


def detect_technologies(target: str, headers: dict | None = None, content: str | None = None) -> list[str]:
    detected = set()
    hdrs = headers or {}
    cnt = content or ""

    # Header fingerprinting
    for h_name, mappings in HEADER_FINGERPRINTS.items():
        h_val = hdrs.get(h_name, "") or hdrs.get(h_name.title(), "") or hdrs.get(h_name.lower(), "")
        if h_val:
            for pattern, tech in mappings.items():
                if pattern.lower() in str(h_val).lower():
                    detected.add(tech)

    # Content / Body fingerprinting
    cnt_lower = cnt.lower()
    if "__viewstate" in cnt_lower or ".aspx" in cnt_lower or "asp.net" in cnt_lower:
        detected.add("ASP.NET")
    if "react" in cnt_lower or "_next/static" in cnt_lower or "data-reactroot" in cnt_lower:
        detected.add("React")
    if "_next/static" in cnt_lower or "__next_data__" in cnt_lower:
        detected.add("Next.js")
    if "spring" in cnt_lower or "whitelabel error page" in cnt_lower:
        detected.add("Spring Boot")
    if "graphql" in cnt_lower or "apollo" in cnt_lower:
        detected.add("GraphQL")
    if "<app-root" in cnt_lower or "ng-version" in cnt_lower or "ng-app" in cnt_lower or "angular" in cnt_lower or "polyfills.js" in cnt_lower:
        detected.add("Angular")
    if "vue" in cnt_lower or "data-v-" in cnt_lower or "nuxt" in cnt_lower:
        detected.add("Vue.js")
    if "owasp juice shop" in cnt_lower or "juice-shop" in cnt_lower or "bkimminich" in cnt_lower:
        detected.add("OWASP Juice Shop")
        detected.add("Node.js")
        detected.add("Express")
        detected.add("Angular")
    if "wp-content" in cnt_lower or "wp-includes" in cnt_lower or "wordpress" in cnt_lower:
        detected.add("WordPress")
    if "laravel" in cnt_lower:
        detected.add("Laravel")
    if "django" in cnt_lower or "csrfmiddlewaretoken" in cnt_lower:
        detected.add("Django")

    # Save to engagement memory if available
    d = _get_eng_dir()
    if d.exists():
        t_file = d / "technologies.json"
        existing = {}
        if t_file.exists():
            try:
                existing = json.loads(t_file.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        if not isinstance(existing, dict):
            existing = {}

        frameworks = set(existing.get("frameworks", []))
        servers = set(existing.get("servers", []))
        apis = set(existing.get("APIs", []))

        server_names = {"IIS", "nginx", "Apache", "Cloudflare", "CloudFront", "LiteSpeed", "Kestrel", "Caddy", "Gunicorn", "Uvicorn", "OpenResty"}
        api_names = {"GraphQL", "REST", "gRPC", "OpenAPI", "Swagger"}

        for t in detected:
            if t in server_names:
                servers.add(t)
            elif t in api_names:
                apis.add(t)
            else:
                frameworks.add(t)

        existing["frameworks"] = sorted(list(frameworks))
        existing["servers"] = sorted(list(servers))
        existing["APIs"] = sorted(list(apis))
        t_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    return sorted(list(detected))
