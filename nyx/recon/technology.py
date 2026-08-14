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
        "Next.js": "Next.js"
    },
    "server": {
        "Microsoft-IIS": "IIS",
        "nginx": "nginx",
        "Apache": "Apache"
    }
}


def detect_technologies(target: str, headers: dict | None = None, content: str | None = None) -> list[str]:
    detected = set()
    hdrs = headers or {}
    cnt = content or ""

    # Header fingerprinting
    for h_name, mappings in HEADER_FINGERPRINTS.items():
        h_val = hdrs.get(h_name, "") or hdrs.get(h_name.title(), "")
        if h_val:
            for pattern, tech in mappings.items():
                if pattern.lower() in h_val.lower():
                    detected.add(tech)

    # Content / Body fingerprinting
    cnt_lower = cnt.lower()
    if "__viewstate" in cnt_lower or ".aspx" in cnt_lower:
        detected.add("ASP.NET")
    if "react" in cnt_lower or "_next/static" in cnt_lower:
        detected.add("React")
    if "_next/static" in cnt_lower:
        detected.add("Next.js")
    if "spring" in cnt_lower or "whitelabel error page" in cnt_lower:
        detected.add("Spring Boot")
    if "graphql" in cnt_lower:
        detected.add("GraphQL")

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
        frameworks = set(existing.get("frameworks", []))
        for t in detected:
            frameworks.add(t)
        existing["frameworks"] = sorted(list(frameworks))
        t_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    return sorted(list(detected))
