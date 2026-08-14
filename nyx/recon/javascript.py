"""
NYX Recon JavaScript Analysis Intelligence Module
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.recon.normalizer import normalize_endpoint_url


JS_ENDPOINT_REGEX = r'(?:["\'])(/(?:api|v1|v2|graphql|swagger|openapi|auth|login|users|profile|account)[a-zA-Z0-9_\-/\?%&=]*)(?:["\'])'
JS_FILE_REGEX = r'(?:["\'])(/[a-zA-Z0-9_\-/]+\.js(?:\?[a-zA-Z0-9_&=]*)?)(?:["\'])'


def extract_js_files(content_or_html: str, base_url: str = "") -> list[str]:
    files = set()
    for m in re.findall(JS_FILE_REGEX, content_or_html, re.IGNORECASE):
        full_url = f"{base_url.rstrip('/')}{m}" if base_url else m
        files.add(full_url)
    return sorted(list(files))


def extract_endpoints_from_js(js_content: str) -> list[str]:
    endpoints = set()
    for m in re.findall(JS_ENDPOINT_REGEX, js_content, re.IGNORECASE):
        norm = normalize_endpoint_url(m)
        if norm:
            endpoints.add(norm)
    return sorted(list(endpoints))


def extract_api_routes(js_content: str) -> list[str]:
    routes = set()
    patterns = [
        r'(?:["\'])(/api/[a-zA-Z0-9_\-/]+)(?:["\'])',
        r'(?:["\'])(/v1/[a-zA-Z0-9_\-/]+)(?:["\'])',
        r'(?:["\'])(/v2/[a-zA-Z0-9_\-/]+)(?:["\'])',
        r'(?:["\'])(/graphql[a-zA-Z0-9_\-/]*)(?:["\'])',
        r'(?:["\'])(/swagger[a-zA-Z0-9_\-/\.]*)(?:["\'])',
        r'(?:["\'])(/openapi[a-zA-Z0-9_\-/\.]*)(?:["\'])'
    ]
    for pat in patterns:
        for m in re.findall(pat, js_content, re.IGNORECASE):
            routes.add(m)

    # Persist to engagement memory if available
    d = _get_eng_dir()
    if d.exists() and routes:
        ep_file = d / "endpoints.json"
        existing = []
        if ep_file.exists():
            try:
                existing = json.loads(ep_file.read_text(encoding="utf-8"))
            except Exception:
                existing = []
        ex_urls = {item.get("url") if isinstance(item, dict) else str(item) for item in existing}
        for r in routes:
            if r not in ex_urls:
                existing.append({"url": r, "source": "js_intelligence", "priority": "HIGH"})
        ep_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    return sorted(list(routes))
