"""
NYX Recon Intelligent URL Normalizer
"""
from __future__ import annotations
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from nyx.infrastructure.urls import normalize_url as base_normalize_url


def normalize_endpoint_url(url: str) -> str:
    """Smart URL normalizer — strips markdown link wrappers, normalizes scheme/host,
    strips fragments, strips default ports, sorts query parameters, and removes trailing slashes
    for path deduplication."""
    if not url:
        return ""

    # Strip markdown wrappers e.g. [url](url)
    clean_url = base_normalize_url(url.strip())

    try:
        parsed = urlparse(clean_url)
        scheme = parsed.scheme.lower() or "http"
        netloc = parsed.netloc.lower()

        # Remove default ports
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        elif netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]

        # Path normalization: collapse multiple slashes, strip trailing slash unless root path
        path = parsed.path
        path = re.sub(r"/+", "/", path)
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]

        # Sort query params
        query = ""
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = [(k, v[0]) if len(v) == 1 else (k, v) for k, v in sorted(params.items())]
            flat_params = []
            for k, val in sorted_params:
                if isinstance(val, list):
                    for v_item in sorted(val):
                        flat_params.append((k, v_item))
                else:
                    flat_params.append((k, val))
            query = urlencode(flat_params)

        normalized = urlunparse((scheme, netloc, path, parsed.params, query, ""))
        return normalized
    except Exception:
        return clean_url


def deduplicate_endpoints(endpoints: list[str]) -> list[str]:
    seen = set()
    deduped = []
    for ep in endpoints:
        norm = normalize_endpoint_url(ep)
        if norm and norm not in seen:
            seen.add(norm)
            deduped.append(norm)
    return deduped
