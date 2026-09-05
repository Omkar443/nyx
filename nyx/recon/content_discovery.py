"""
NYX Recon Content & Unlinked Path Discovery Module
Discovers unlinked files, API routes, admin surfaces, and sensitive resources via curated wordlists and fuzzing.
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from nyx.infrastructure.tools import has_cmd
from nyx.infrastructure.process import run_cmd
from nyx.infrastructure.urls import normalize_url
from nyx.security.authorization import is_hostname_in_scope

# Curated high-signal wordlist for unlinked asset & path discovery (focused, fast, non-exhaustive)
COMMON_CONTENT_WORDLIST = [
    # Configuration, source & metadata
    ".env", ".git/HEAD", ".git/config", ".gitignore", "config.json", "config.js",
    "settings.py", "web.config", ".well-known/security.txt", ".well-known/jwks.json", "crossdomain.xml",
    "package.json", "package-lock.json", "composer.json", "pom.xml",
    # API definitions & Swagger/OpenAPI documentation
    "swagger.json", "swagger.yaml", "swagger.yml", "openapi.json", "openapi.yaml",
    "api-docs", "api-docs/", "api/docs", "docs/", "swagger-ui.html", "swagger-ui/",
    # Core APIs, Microservices & GraphQL
    "graphql", "graphql/", "graphiql", "api/graphql", "api/", "api/v1/", "api/v2/", "api/v3/",
    "identity/", "community/", "workshop/", "chatbot/", "mailhog/",
    "api/auth/", "api/user/", "api/shop/", "api/vehicle/", "api/mechanic/", "api/merchant/",
    "admin", "admin/", "administrator", "login", "auth", "oauth", "sso",
    # File directories, backups & storage
    "ftp/", "ftp/legal.md", "ftp/acquisitions.md", "uploads/", "files/", "backup/",
    "backup.zip", "backup.sql", "dump.sql", "access.log", "error.log", "debug.log",
    "trace.axd", "elmah.axd",
    # Monitoring, health & system metrics
    "actuator", "actuator/health", "actuator/env", "health", "metrics", "status", "server-status",
    # Specific unlinked discovery assets & detection rules
    "robots.txt", "sitemap.xml", ".sigma", "legal.md"
]

SKIP_HOST_PATTERNS = [
    (re.compile(r"(?:^|[.-])(?:cdn|static(?:-assets)?|assets|digitalassets|images)(?:[.-]|$)", re.IGNORECASE), "CDN/Static Asset Host"),
    (re.compile(r"(?:telemetry|streaming|live-data|fleetview|signaling|npu|hermes-stream)", re.IGNORECASE), "Telemetry/Streaming Gateway"),
    (re.compile(r"(?:^|[.-])(?:s3|\.s3|-files|vehicle-files)(?:[.-]|$)", re.IGNORECASE), "Object Storage/File Bucket"),
]


def should_skip_content_discovery(url: str, metadata: dict[str, Any] | None = None) -> tuple[bool, str]:
    """Determine if a URL/host should be skipped from heavy content discovery.
    
    Skips CDN/static asset hosts, telemetry/streaming endpoints, object storage buckets,
    and dead/unreachable origin services (HTTP 502/503/504).
    """
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or url).lower()

    if metadata:
        code = metadata.get("code") or metadata.get("status")
        if code in (502, 503, 504):
            return True, f"Dead/Unreachable Origin (HTTP {code})"

    for pattern, reason in SKIP_HOST_PATTERNS:
        if pattern.search(host):
            return True, reason

    return False, ""


def extract_spa_routes(base_url: str, timeout: int = 4, max_scripts: int = 5) -> list[dict[str, Any]]:
    """Crawl and extract API endpoints referenced in client-side HTML and JavaScript bundles."""
    discovered: list[dict[str, Any]] = []
    clean_base = base_url.split("#")[0].rstrip("/")
    if not is_hostname_in_scope(clean_base):
        return discovered

    try:
        req = urllib.request.Request(
            clean_base,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NYX-ContentDiscovery/2.2",
                "Accept": "*/*"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return discovered

    # 1. Extract script tags from HTML
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    script_urls = []
    for s in scripts:
        if s.startswith("//"):
            script_urls.append(f"http:{s}")
        elif s.startswith("http://") or s.startswith("https://"):
            script_urls.append(s)
        else:
            script_urls.append(f"{clean_base}/{s.lstrip('/')}")

    # 2. Extract inline routes from HTML
    inline_matches = re.findall(r'["\'](/(?:identity|community|workshop|chatbot|api|v[0-9]|auth|user|admin)[^"\'\s<>{}]+)["\']', html)
    seen_paths = set()
    for ep in inline_matches:
        ep_clean = ep.split("?")[0].rstrip("/")
        if ep_clean and ep_clean not in seen_paths and not ep_clean.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff")):
            seen_paths.add(ep_clean)
            discovered.append({
                "url": f"{clean_base}{ep_clean}",
                "path": ep_clean,
                "status": 200,
                "title": "SPA Inline Route",
                "source": "content_discovery",
                "discovery_method": "spa_html_inline"
            })

    # 3. Extract HTML hyperlinks and form actions (classic & modern web applications)
    href_matches = re.findall(r'(?:href|action)=["\']([^"\'#\s>]+)["\']', html, re.IGNORECASE)
    seen_urls = {d["url"] for d in discovered}
    for h in href_matches:
        if h.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            continue
        if h.startswith("http://") or h.startswith("https://"):
            full_link = h
        else:
            full_link = urllib.parse.urljoin(f"{clean_base}/", h)

        if is_hostname_in_scope(full_link) and full_link not in seen_urls:
            p_obj = urllib.parse.urlparse(full_link)
            path_str = p_obj.path or "/"
            if not path_str.lower().endswith((".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map", ".ttf", ".eot")):
                seen_urls.add(full_link)
                discovered.append({
                    "url": full_link,
                    "path": path_str,
                    "status": 200,
                    "title": "HTML Discovered Link",
                    "source": "content_discovery",
                    "discovery_method": "html_link_crawl"
                })

    # 4. Fetch each JS bundle and extract API routes
    api_patterns = [
        r'["\']((?:/)?(?:api|identity|community|workshop|chatbot|v\d+|auth|user|vehicle|mechanic|merchant|shop|order|orders|coupon|management)/[a-zA-Z0-9_\-\/\.]+)["\']',
        r'`((?:/)?(?:api|identity|community|workshop|chatbot|v\d+|auth|user|vehicle|mechanic|merchant|shop|order|orders|coupon|management)/[^`\s<>{}]+)`',
        r'["\']((?:/)?(?:api|identity|community|workshop|chatbot)/[^"\'\s<>{}`]+)["\']',
    ]

    # 4. Fetch each JS bundle concurrently and extract API routes
    def _script_priority(url_str: str) -> int:
        u_lower = url_str.lower()
        if any(k in u_lower for k in ("app", "main", "bundle", "runtime", "index")):
            return 0
        if any(k in u_lower for k in ("chunk", "vendor", "common", "api")):
            return 1
        return 2

    scoped_scripts = [s for s in script_urls if is_hostname_in_scope(s)]
    scoped_scripts.sort(key=_script_priority)
    chosen_scripts = scoped_scripts[:max_scripts]

    def _fetch_and_parse_js(s_url: str) -> list[dict[str, Any]]:
        extracted = []
        try:
            req = urllib.request.Request(
                s_url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NYX-ContentDiscovery/2.2",
                    "Accept": "*/*"
                }
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                js_content = resp.read().decode("utf-8", errors="replace")

            for pat in api_patterns:
                for match in re.finditer(pat, js_content):
                    path_found = match.group(1).strip()
                    path_clean = re.sub(r"\$\{[^}]*\}", "1", path_found)
                    path_clean = path_clean.split("?")[0].split("#")[0].rstrip("/")
                    if path_clean and not path_clean.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".map", ".html", ".htm")):
                        if not path_clean.startswith("/"):
                            path_clean = f"/{path_clean}"
                        if len(path_clean) > 2:
                            extracted.append({
                                "url": f"{clean_base}{path_clean}",
                                "path": path_clean,
                                "status": 200,
                                "title": "SPA Discovered API Endpoint",
                                "source": "content_discovery",
                                "discovery_method": "spa_js_bundle_extraction"
                            })
        except Exception:
            pass
        return extracted

    if chosen_scripts:
        with ThreadPoolExecutor(max_workers=min(5, len(chosen_scripts))) as js_pool:
            futures = [js_pool.submit(_fetch_and_parse_js, u) for u in chosen_scripts]
            for fut in as_completed(futures):
                try:
                    for item in fut.result():
                        if item["path"] not in seen_paths:
                            seen_paths.add(item["path"])
                            discovered.append(item)
                except Exception:
                    pass

    return discovered


def probe_single_path(base_url: str, path: str, timeout: int = 4) -> dict[str, Any] | None:
    """Probe a single URL path to discover unlinked content."""
    clean_base = base_url.split("#")[0].rstrip("/")
    clean_path = path.lstrip("/")
    url = f"{clean_base}/{clean_path}"

    if not is_hostname_in_scope(url):
        return None

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NYX-ContentDiscovery/2.2",
                "Accept": "*/*"
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            headers = dict(resp.headers)
            body = resp.read()[:4096].decode("utf-8", errors="replace")

            title = ""
            m = re.search(r"<title[^>]*>([^<]*)</title>", body, re.IGNORECASE)
            if m:
                title = m.group(1).strip()[:80]

            return {
                "url": url,
                "path": f"/{clean_path}",
                "status": status,
                "server": headers.get("Server", ""),
                "content_type": headers.get("Content-Type", ""),
                "title": title,
                "length": len(body),
                "source": "content_discovery",
                "discovery_method": "wordlist_probe"
            }
    except urllib.error.HTTPError as e:
        # Non-404 responses (e.g. 401 Unauthorized, 403 Forbidden, 405 Method Not Allowed, 500 Internal Error) indicate the path exists
        if e.code in (401, 403, 405, 500, 301, 302, 307):
            return {
                "url": url,
                "path": f"/{clean_path}",
                "status": e.code,
                "server": dict(e.headers).get("Server", ""),
                "title": f"HTTP {e.code}",
                "source": "content_discovery",
                "discovery_method": "wordlist_probe"
            }
        return None
    except Exception:
        return None


def detect_uniform_waf_block(
    probes: list[dict[str, Any]],
    meta: dict[str, Any] | None = None,
    threshold_ratio: float = 0.80,
    min_count: int = 5,
) -> tuple[bool, int | None]:
    """Detect if a high proportion of wordlist probes return the identical error/block status.
    
    A uniform status code (e.g., 403 Forbidden, 406 Not Acceptable, 429 Too Many Requests, 503)
    across >= 80% of responses (minimum 5 probes) is a strong signal of blanket WAF
    blocking or catch-all default rejection, rather than legitimate discovered endpoints.
    """
    if not probes:
        return False, None

    from collections import Counter
    status_counts = Counter(p.get("status") for p in probes)
    most_common_status, count = status_counts.most_common(1)[0]

    # Only treat blocking/error status codes as potential WAF blanket blocks
    if most_common_status in (401, 403, 406, 429, 500, 502, 503):
        ratio = count / len(probes)
        if count >= min_count and ratio >= threshold_ratio:
            return True, most_common_status

    # If base endpoint itself was blocked (e.g. 403), any cluster matching that code is a catch-all
    if meta and meta.get("code") in (401, 403, 406, 429):
        base_code = meta.get("code")
        if status_counts.get(base_code, 0) >= min_count and (status_counts[base_code] / len(probes)) >= 0.70:
            return True, base_code

    return False, None


def run_content_discovery(
    base_urls: list[str | dict[str, Any]],
    wordlist: list[str] | None = None,
    max_workers: int = 5,
    timeout: int = 4,
    endpoint_budget_seconds: float = 8.0,
    endpoint_metadata: dict[str, dict[str, Any]] | None = None,
    progress_callback: Any | None = None,
) -> list[dict[str, Any]]:
    """Execute content discovery against live base URLs combining wordlist fuzzing and SPA JS bundle analysis."""
    paths_to_test = wordlist or COMMON_CONTENT_WORDLIST
    discovered_map: dict[str, dict[str, Any]] = {}
    total_endpoints = len(base_urls)

    for idx, base in enumerate(base_urls):
        if isinstance(base, dict):
            clean_base = (base.get("url") or "").split("#")[0].rstrip("/")
            meta = base
        else:
            clean_base = str(base).split("#")[0].rstrip("/")
            meta = endpoint_metadata.get(clean_base) if endpoint_metadata else None

        if not clean_base:
            continue

        # Smart Scope & Host Filtering
        skip, reason = should_skip_content_discovery(clean_base, meta)
        if skip:
            if progress_callback:
                try:
                    progress_callback(idx, total_endpoints, clean_base, len(discovered_map), f"Skipped ({reason})")
                except Exception:
                    pass
            continue

        if progress_callback:
            try:
                progress_callback(idx, total_endpoints, clean_base, len(discovered_map), "Probing")
            except Exception:
                pass

        t_endpoint_start = time.time()

        # 1. SPA & JS Bundle Endpoint Extraction (concurrent JS bundle downloads)
        spa_time_budget = max(1.5, endpoint_budget_seconds * 0.4)
        spa_timeout = min(timeout, max(1, int(spa_time_budget)))
        spa_routes = extract_spa_routes(clean_base, timeout=spa_timeout, max_scripts=5)
        for r in spa_routes:
            discovered_map[r["url"]] = r

        # 2. Wordlist Probing with strict per-endpoint budget enforcement
        elapsed = time.time() - t_endpoint_start
        remaining_budget = endpoint_budget_seconds - elapsed
        if remaining_budget > 1.0:
            probe_timeout = min(timeout, max(1, int(remaining_budget)))
            endpoint_probes: list[dict[str, Any]] = []
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(probe_single_path, clean_base, p, probe_timeout): p
                    for p in paths_to_test
                }
                for fut in as_completed(futures):
                    if time.time() - t_endpoint_start > endpoint_budget_seconds:
                        for pending in futures:
                            pending.cancel()
                        break
                    try:
                        res = fut.result()
                        if res and res.get("url"):
                            endpoint_probes.append(res)
                    except Exception:
                        pass

            # Detect uniform WAF / catch-all blocking
            is_waf_block, block_code = detect_uniform_waf_block(endpoint_probes, meta=meta)
            if is_waf_block:
                if progress_callback:
                    try:
                        progress_callback(
                            idx, total_endpoints, clean_base, len(discovered_map),
                            f"WAF Block Filtered ({block_code})"
                        )
                    except Exception:
                        pass
                # Discard the uniform WAF block false-positives; keep any probes that differ
                for res in endpoint_probes:
                    if res.get("status") != block_code:
                        discovered_map[res["url"]] = res
            else:
                for res in endpoint_probes:
                    discovered_map[res["url"]] = res

    return sorted(list(discovered_map.values()), key=lambda x: x["url"])
