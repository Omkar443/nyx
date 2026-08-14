"""
NYX Recon Crawler & Path Extractor Module
"""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse
from nyx.recon.normalizer import normalize_endpoint_url


def extract_links(html_content: str, base_url: str) -> list[str]:
    links = set()
    if not html_content:
        return []

    # Match href and src attributes
    pattern = r'(?:href|src)=["\']([^"\']+)["\']'
    for match in re.findall(pattern, html_content, re.IGNORECASE):
        if match.startswith("javascript:") or match.startswith("data:"):
            continue
        full_url = urljoin(base_url, match)
        norm = normalize_endpoint_url(full_url)
        if norm:
            links.add(norm)

    return sorted(list(links))


def collect_paths(endpoints: list[str]) -> list[str]:
    paths = set()
    for ep in endpoints:
        parsed = urlparse(ep)
        if parsed.path:
            paths.add(parsed.path)
    return sorted(list(paths))
