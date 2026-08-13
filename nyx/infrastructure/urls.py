"""
NYX Infrastructure URL Utilities
"""
from __future__ import annotations
import re
import urllib.parse


def normalize_url(raw_url: str) -> str:
    """Central URL normalization function for recon ingestion and memory persistence.
    - Strips Markdown links (e.g. [http://example.com](http://example.com) -> http://example.com)
    - Normalizes scheme (lowercased)
    - Normalizes hostname (lowercased, strips trailing dot, strips default ports :80 and :443)
    - Preserves path and query parameters
    - Normalizes trailing slashes (preserves root slash '/', strips trailing slash from non-root paths)
    """
    if not isinstance(raw_url, str):
        return str(raw_url) if raw_url is not None else ""

    url = raw_url.strip()
    if not url:
        return ""

    md_match = re.search(r'\[.*?\]\((https?://[^\s\)]+)\)', url, re.I)
    if md_match:
        url = md_match.group(1).strip()
    else:
        url = re.sub(r'^\[(https?://[^\]]+)\]$', r'\1', url, flags=re.I).strip()

    has_scheme = bool(re.match(r'^https?://', url, re.I))
    parse_target = url if has_scheme else ("http://" + url)

    try:
        parsed = urllib.parse.urlparse(parse_target)
        scheme = (parsed.scheme or "http").lower()
        netloc = parsed.netloc.lower()

        if "." in netloc:
            if ":" in netloc:
                host, port = netloc.rsplit(":", 1)
                host = host.rstrip(".")
                if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                    netloc = host
                else:
                    netloc = f"{host}:{port}"
            else:
                netloc = netloc.rstrip(".")

        path = parsed.path
        if path and len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")

        query = parsed.query
        fragment = parsed.fragment

        if has_scheme:
            res = f"{scheme}://{netloc}{path}"
        else:
            res = f"{netloc}{path}"

        if query:
            res += f"?{query}"
        if fragment:
            res += f"#{fragment}"

        return res
    except Exception:
        return url
