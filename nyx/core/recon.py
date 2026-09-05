"""
NYX Core Recon Module
Canonical business logic for passive recon, subdomain discovery, DNS resolution, HTTP probing, and engagement sync.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from nyx.infrastructure.filesystem import REPO_ROOT, _get_eng_dir
from nyx.infrastructure.process import run_cmd
from nyx.infrastructure.tools import has_cmd
from nyx.infrastructure.urls import normalize_url
from nyx.recon.intelligence import run_recon_intelligence
from nyx.recon.content_discovery import run_content_discovery
from nyx.security.authorization import is_hostname_in_scope
from nyx.infrastructure.logging import get_logger

logger = get_logger("nyx.recon")

_HTTP_OPENER: urllib.request.OpenerDirector | None = None


def configure_http_proxy(
    proxy_url: str | None = None, insecure: bool = False
) -> tuple[bool, str]:
    global _HTTP_OPENER
    if not proxy_url:
        burp_env = os.environ.get("NYX_BURP_PROXY")
        if burp_env:
            proxy_url, insecure = burp_env, True
        else:
            proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if not proxy_url:
        _HTTP_OPENER = None
        return False, "direct (no proxy)"

    import ssl

    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    proxy_handler = urllib.request.ProxyHandler(
        {"http": proxy_url, "https": proxy_url}
    )
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    _HTTP_OPENER = urllib.request.build_opener(proxy_handler, https_handler)
    return True, f"via proxy {proxy_url} ({'TLS verify OFF' if insecure else 'TLS verify on'})"


def detect_burp() -> str | None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=1) as r:
            if r.status == 200:
                return "http://127.0.0.1:8080"
    except Exception:
        pass
    return None


def http_get(
    url: str, timeout: int = 5, headers: dict | None = None
) -> tuple[int, dict, str]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        if _HTTP_OPENER is not None:
            with _HTTP_OPENER.open(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
                return r.status, dict(r.headers), body
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return 0, {}, str(e)


def recon_subdomains_via_crtsh(target: str, timeout: int | None = None, retries: int = 1) -> set[str]:
    env_timeout = os.environ.get("NYX_CRTSH_TIMEOUT")
    actual_timeout = timeout or (int(env_timeout) if env_timeout and env_timeout.isdigit() else 30)
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    for attempt in range(retries + 1):
        status, _, body = http_get(url, timeout=actual_timeout)
        if status == 200 and body:
            try:
                rows = json.loads(body)
                subs = set()
                for r in rows:
                    nv = (r.get("name_value") or "").lower()
                    for line in nv.split("\n"):
                        line = line.strip()
                        if line and "*" not in line:
                            subs.add(line)
                if subs:
                    return subs
            except Exception:
                pass
        if attempt < retries:
            import time
            time.sleep(1.0)
    return set()


def recon_subdomains_via_subfinder(target: str, timeout: int | None = None) -> set[str]:
    if not has_cmd("subfinder"):
        return set()
    env_timeout = os.environ.get("NYX_SUBFINDER_TIMEOUT")
    actual_timeout = timeout or (int(env_timeout) if env_timeout and env_timeout.isdigit() else 180)

    import tempfile
    with tempfile.NamedTemporaryFile(prefix="nyx_subfinder_", suffix=".txt", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    subs = set()
    try:
        cmd = ["subfinder", "-d", target, "-silent", "-o", str(tmp_path)]
        ret, out, _ = run_cmd(cmd, timeout=actual_timeout)
        if tmp_path.exists():
            for line in tmp_path.read_text(encoding="utf-8", errors="replace").splitlines():
                l = line.strip().lower()
                if l and not l.startswith("*"):
                    subs.add(l)
        if out:
            for line in out.splitlines():
                l = line.strip().lower()
                if l and not l.startswith("*"):
                    subs.add(l)
        return subs
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass


def recon_resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        return sorted(set(i[4][0] for i in infos))
    except Exception:
        return []


def recon_http_probe(host_or_url: str) -> dict | None:
    from nyx.recon.technology import detect_technologies

    # Case 1: Explicit full URL
    if host_or_url.startswith("http://") or host_or_url.startswith("https://"):
        parsed = urllib.parse.urlparse(host_or_url)
        host = parsed.netloc.split(":")[0] if parsed.netloc else host_or_url
        code, headers, body = http_get(host_or_url, timeout=4)
        if code != 0:
            title = ""
            m = re.search(r"<title[^>]*>([^<]*)</title>", body[:8192], re.I)
            if m:
                title = m.group(1).strip()[:80]
            techs = detect_technologies(host_or_url, headers=headers, content=body)
            return {
                "url": host_or_url,
                "host": host,
                "code": code,
                "server": headers.get("Server", ""),
                "title": title,
                "powered_by": headers.get("X-Powered-By", ""),
                "drupal_cache": headers.get("X-Drupal-Cache", ""),
                "technologies": techs,
                "tech": techs,
            }
        return None

    # Case 2: Contains path component (e.g. "server.vulnapp.id/mutillidae")
    if "/" in host_or_url:
        parts = host_or_url.split("/", 1)
        host = parts[0].split(":")[0]
        subpath = "/" + parts[1].strip("/")
        for scheme in ("https", "http"):
            url = f"{scheme}://{parts[0]}{subpath}"
            code, headers, body = http_get(url, timeout=4)
            if code == 0:
                continue
            title = ""
            m = re.search(r"<title[^>]*>([^<]*)</title>", body[:8192], re.I)
            if m:
                title = m.group(1).strip()[:80]
            techs = detect_technologies(url, headers=headers, content=body)
            return {
                "url": url,
                "host": host,
                "code": code,
                "server": headers.get("Server", ""),
                "title": title,
                "powered_by": headers.get("X-Powered-By", ""),
                "drupal_cache": headers.get("X-Drupal-Cache", ""),
                "technologies": techs,
                "tech": techs,
            }
        return None

    # Case 3: Pure host or host:port
    host = host_or_url.split(":")[0]
    for scheme in ("https", "http"):
        url = f"{scheme}://{host_or_url}/"
        code, headers, body = http_get(url, timeout=4)
        if code == 0:
            continue
        title = ""
        m = re.search(r"<title[^>]*>([^<]*)</title>", body[:8192], re.I)
        if m:
            title = m.group(1).strip()[:80]
        techs = detect_technologies(url, headers=headers, content=body)
        return {
            "url": url,
            "host": host,
            "code": code,
            "server": headers.get("Server", ""),
            "title": title,
            "powered_by": headers.get("X-Powered-By", ""),
            "drupal_cache": headers.get("X-Drupal-Cache", ""),
            "technologies": techs,
            "tech": techs,
        }
    return None


def write_recon_summary(
    target: str,
    subs: set[str],
    resolved: dict,
    live: list,
    out: Path,
    content_discovered: list[dict] | None = None,
):
    cd_list = content_discovered or []
    lines = [
        f"# Recon — {target}",
        "",
        f"_Generated by NYX Recon at {datetime.datetime.now().isoformat(timespec='seconds')}._",
        "",
        "## Attack-surface snapshot",
        "",
        f"- Subdomains discovered (passive): **{len(subs)}**",
        f"- DNS-resolved: **{len(resolved)}**",
        f"- HTTP-live: **{len(live)}**",
        f"- Content-discovered (unlinked paths): **{len(cd_list)}**",
        "",
        "## Live hosts",
        "",
        "| Host | URL | Code | Server | Title |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(live, key=lambda x: x.get("host", "")):
        title = (r.get("title") or "").replace("|", "\\|")[:50]
        code_val = r.get("code", r.get("status", ""))
        lines.append(
            f"| `{r.get('host', '')}` | {r.get('url', '')} | {code_val} | {r.get('server','')} | {title} |"
        )

    if cd_list:
        lines += [
            "",
            "## Content discovery (unlinked paths)",
            "",
            "| URL | Path | Code | Server | Method |",
            "|---|---|---|---|---|",
        ]
        for cd in sorted(cd_list, key=lambda x: x.get("url", "")):
            lines.append(
                f"| {cd.get('url')} | `{cd.get('path')}` | {cd.get('status')} | {cd.get('server','')} | `{cd.get('discovery_method','wordlist_probe')}` |"
            )

    lines += [
        "",
        "## Suggested next moves",
        "",
        "- For each live host and unlinked endpoint, run `nyx classify https://<host>/<path>?<params>` to surface attack candidates.",
        "- Cross-TLD pivot: check JS bundles for sister-domain references.",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")


PRODUCER = "nyx-recon/2.1.0"
_P1_HINTS = (
    "api.",
    "api-",
    "graphql",
    "auth.",
    "sso.",
    "login.",
    "account.",
    "admin.",
    "internal.",
    "intranet.",
    "staging.",
    "stage.",
    "dev.",
    "test.",
    "uat.",
    "qa.",
    "gateway.",
    "gw.",
    "vpn.",
    "portal.",
)
_KILL_HINTS = ("cdn.", "static.", "assets.", "img.", "images.", "media.", "fonts.")


def _rank_host(host: str) -> tuple[str, str]:
    h = host.lower()
    if any(k in h for k in _P1_HINTS):
        return "P1", "high-value surface (api/auth/admin/non-prod)"
    if any(h.startswith(k) for k in _KILL_HINTS):
        return "KILL", "static/CDN host — low yield"
    return "P2", "standard web surface"


def build_manifest(
    target: str,
    subs: set,
    resolved: dict,
    live: list,
    content_discovered: list[dict] | None = None,
) -> dict:
    cd_list = content_discovered or []
    live_by_host = {r["host"]: r for r in live}
    assets = []
    for host in sorted(live_by_host):
        r = live_by_host[host]
        assets.append(
            {
                "host": host,
                "ips": resolved.get(host, []),
                "url": r.get("url"),
                "status": r.get("code"),
                "server": r.get("server", ""),
                "title": r.get("title", ""),
                "tech": r.get("tech", []),
                "source": "crtsh+httpx",
            }
        )
    for host in sorted(resolved):
        if host not in live_by_host:
            assets.append(
                {
                    "host": host,
                    "ips": resolved[host],
                    "url": None,
                    "status": None,
                    "server": "",
                    "title": "",
                    "tech": [],
                    "source": "crtsh+dns",
                }
            )

    ranked = []
    for host in sorted(live_by_host):
        r = live_by_host[host]
        prio, why = _rank_host(host)
        bug_classes = []
        ranked.append(
            {
                "url": r.get("url"),
                "host": host,
                "bug_classes": bug_classes,
                "priority": prio,
                "rationale": why,
            }
        )
    _order = {"P1": 0, "P2": 1, "KILL": 2}
    ranked.sort(key=lambda x: (_order.get(x["priority"], 9), x["host"]))

    return {
        "schema_version": "1.0",
        "target": target,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "producers": [PRODUCER],
        "counts": {
            "subdomains": len(subs),
            "resolved": len(resolved),
            "live": len(live),
            "content_discovered": len(cd_list),
        },
        "assets": assets,
        "content_discovery": cd_list,
        "ranked_surface": ranked,
        "secrets": [],
        "identity_fabric": {},
    }


def sync_recon_to_engagement(
    target: str,
    subs: set,
    resolved: dict,
    live: list,
    content_discovered: list[dict] | None = None,
    base_dir: Path | None = None,
) -> tuple[int, int, int]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return 0, 0, 0

    from nyx.core.engagement import get_engagement_target
    active_target = get_engagement_target(base_dir=base_dir)
    if active_target:
        from nyx.ai.context import _matches_target_endpoint
        from nyx.security.authorization import parse_target_tuple, is_authorized_target
        _, t_host, _ = parse_target_tuple(target)
        _, a_host, _ = parse_target_tuple(active_target)
        matches_active = (t_host and a_host == t_host) or _matches_target_endpoint(target, active_target) or _matches_target_endpoint(active_target, target)
        if not matches_active and not is_authorized_target(target, base_dir=base_dir):
            # Active target has switched and background recon target is no longer authorized/active: discard to prevent pollution
            return 0, 0, 0

    ep_file = d / "endpoints.json"
    try:
        endpoints = (
            json.loads(ep_file.read_text(encoding="utf-8")) if ep_file.exists() else []
        )
    except Exception:
        endpoints = []

    existing_by_url = {
        e.get("url", "").strip().lower(): e for e in endpoints if e.get("url")
    }
    cd_list = content_discovered or []
    total_disc = len(live) + len(resolved) + len(cd_list)
    new_cnt = 0
    known_cnt = 0

    for rec in live:
        url = normalize_url(rec.get("url") or "")
        if not url:
            continue
        key = url.lower()
        if key in existing_by_url:
            known_cnt += 1
            existing_obj = existing_by_url[key]
            sources = existing_obj.setdefault(
                "sources",
                [
                    "recon"
                    if existing_obj.get("source") == "recon"
                    else "manual"
                ],
            )
            if "recon" not in sources:
                sources.append("recon")
            existing_obj["status"] = rec.get("code") or existing_obj.get("status")
            existing_obj["server"] = rec.get("server") or existing_obj.get("server")
            if rec.get("title") and not existing_obj.get("title"):
                existing_obj["title"] = rec["title"]
        else:
            new_cnt += 1
            new_obj = {
                "url": url,
                "target": target,
                "host": rec.get("host"),
                "status": rec.get("code"),
                "server": rec.get("server", ""),
                "title": rec.get("title", ""),
                "priority": _rank_host(rec.get("host", ""))[0],
                "source": "recon",
                "sources": ["recon"],
                "added_at": datetime.datetime.now().isoformat(),
            }
            endpoints.append(new_obj)
            existing_by_url[key] = new_obj

    for host, ips in resolved.items():
        url = f"https://{host}"
        key = url.lower()
        if key not in existing_by_url:
            new_cnt += 1
            new_obj = {
                "url": url,
                "target": target,
                "host": host,
                "ips": ips,
                "status": None,
                "priority": _rank_host(host)[0],
                "source": "recon",
                "sources": ["recon"],
                "added_at": datetime.datetime.now().isoformat(),
            }
            endpoints.append(new_obj)
            existing_by_url[key] = new_obj
        else:
            known_cnt += 1

    for cd in cd_list:
        raw_cd_url = cd.get("url") or ""
        url = normalize_url(raw_cd_url)
        if not url:
            continue
        key = url.lower()
        if key in existing_by_url:
            known_cnt += 1
            existing_obj = existing_by_url[key]
            sources = existing_obj.setdefault("sources", [existing_obj.get("source") or "content_discovery"])
            if "content_discovery" not in sources:
                sources.append("content_discovery")
            if cd.get("status") is not None:
                existing_obj["status"] = cd.get("status")
            if cd.get("server") and not existing_obj.get("server"):
                existing_obj["server"] = cd.get("server")
            if cd.get("title") and not existing_obj.get("title"):
                existing_obj["title"] = cd["title"]
        else:
            new_cnt += 1
            p = urllib.parse.urlparse(url)
            host = p.netloc.split(":")[0] if p.netloc else target
            prio = "P1" if any(k in url.lower() for k in ("admin", "api", "auth", "secret", "env", "graphql", "ftp", "doc", "sigma")) else "P2"
            new_obj = {
                "url": url,
                "target": target,
                "host": host,
                "status": cd.get("status"),
                "server": cd.get("server", ""),
                "title": cd.get("title", ""),
                "priority": prio,
                "source": "content_discovery",
                "sources": ["content_discovery"],
                "discovery_method": cd.get("discovery_method", "wordlist_probe"),
                "added_at": datetime.datetime.now().isoformat(),
            }
            endpoints.append(new_obj)
            existing_by_url[key] = new_obj

    ep_file.write_text(json.dumps(endpoints, indent=2), encoding="utf-8")

    # Sync detected technologies into .engagement/technologies.json
    tech_candidates: set[str] = set()
    for rec in live:
        h_techs = rec.get("technologies") or rec.get("tech") or []
        for t in h_techs:
            if t:
                tech_candidates.add(t)
    for cd in cd_list:
        c_techs = cd.get("technologies") or cd.get("tech") or []
        for t in c_techs:
            if t:
                tech_candidates.add(t)

    if tech_candidates:
        t_file = d / "technologies.json"
        existing_tech = {}
        if t_file.exists():
            try:
                existing_tech = json.loads(t_file.read_text(encoding="utf-8"))
            except Exception:
                existing_tech = {}
        if not isinstance(existing_tech, dict):
            existing_tech = {}
        frameworks = set(existing_tech.get("frameworks", []))
        servers = set(existing_tech.get("servers", []))
        apis = set(existing_tech.get("APIs", []))

        server_names = {"IIS", "nginx", "Apache", "Cloudflare", "CloudFront", "LiteSpeed", "Kestrel", "Caddy", "Gunicorn", "Uvicorn", "OpenResty"}
        api_names = {"GraphQL", "REST", "gRPC", "OpenAPI", "Swagger"}

        for t in tech_candidates:
            if t in server_names:
                servers.add(t)
            elif t in api_names:
                apis.add(t)
            else:
                frameworks.add(t)

        existing_tech["frameworks"] = sorted(list(frameworks))
        existing_tech["servers"] = sorted(list(servers))
        existing_tech["APIs"] = sorted(list(apis))
        t_file.write_text(json.dumps(existing_tech, indent=2), encoding="utf-8")

    return total_disc, new_cnt, known_cnt


def sync_exec_to_engagement(
    execution_result: dict,
    base_dir: Path | None = None,
) -> tuple[int, int]:
    """Sync tool execution results into engagement memory (.engagement/endpoints.json).

    Handles Katana-style endpoint lists and httpx-style host probe outputs.
    Returns (new_count, known_count).
    """
    if not isinstance(execution_result, dict):
        return 0, 0

    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return 0, 0

    ep_file = d / "endpoints.json"
    try:
        endpoints = (
            json.loads(ep_file.read_text(encoding="utf-8")) if ep_file.exists() else []
        )
    except Exception:
        endpoints = []
    if not isinstance(endpoints, list):
        endpoints = []

    existing_by_url = {
        e.get("url", "").strip().lower(): e for e in endpoints if isinstance(e, dict) and e.get("url")
    }

    meta = execution_result.get("metadata")
    if not isinstance(meta, dict):
        meta = execution_result

    candidates: list[dict] = []

    # 1. Katana style: endpoints list
    ep_list = meta.get("endpoints") or execution_result.get("endpoints")
    if ep_list and isinstance(ep_list, (list, set, tuple)):
        for item in ep_list:
            if isinstance(item, str):
                candidates.append({"url": item})
            elif isinstance(item, dict):
                candidates.append({
                    "url": item.get("url") or item.get("endpoint"),
                    "status": item.get("status") or item.get("status_code"),
                    "title": item.get("title", ""),
                    "server": item.get("server") or item.get("webserver", ""),
                    "host": item.get("host"),
                })

    # 2. Httpx style: live_hosts list
    live_hosts = meta.get("live_hosts") or execution_result.get("live_hosts")
    if live_hosts and isinstance(live_hosts, (list, set, tuple)):
        for item in live_hosts:
            if isinstance(item, dict):
                candidates.append({
                    "url": item.get("url") or item.get("input"),
                    "status": item.get("status") or item.get("status_code") or item.get("status-code"),
                    "title": item.get("title", ""),
                    "server": item.get("webserver") or item.get("server", ""),
                    "host": item.get("host"),
                })
            elif isinstance(item, str):
                candidates.append({"url": item})

    # 3. Direct single host / endpoint style
    if not candidates:
        single_url = meta.get("url") or meta.get("endpoint") or meta.get("input") or execution_result.get("url") or execution_result.get("endpoint")
        if single_url and isinstance(single_url, str):
            candidates.append({
                "url": single_url,
                "status": meta.get("status") or meta.get("status_code") or meta.get("status-code") or execution_result.get("status"),
                "title": meta.get("title", "") or execution_result.get("title", ""),
                "server": meta.get("webserver") or meta.get("server", "") or execution_result.get("server", ""),
                "host": meta.get("host") or execution_result.get("host"),
            })
        elif execution_result.get("target") and isinstance(execution_result.get("target"), str):
            tgt = execution_result.get("target", "").strip()
            if tgt.startswith("http://") or tgt.startswith("https://"):
                candidates.append({"url": tgt})

    new_cnt = 0
    known_cnt = 0

    for rec in candidates:
        raw_url = rec.get("url")
        if not raw_url or not isinstance(raw_url, str):
            continue
        url = normalize_url(raw_url)
        if not url:
            continue
        key = url.lower()

        host = rec.get("host")
        if not host:
            try:
                p = urllib.parse.urlparse(url)
                host = p.netloc.split(":")[0] if p.netloc else ""
            except Exception:
                host = ""

        if not is_hostname_in_scope(host or url, base_dir=base_dir):
            continue

        if key in existing_by_url:
            known_cnt += 1
            existing_obj = existing_by_url[key]
            sources = existing_obj.setdefault(
                "sources",
                [existing_obj.get("source") or "manual"],
            )
            if "exec" not in sources:
                sources.append("exec")
            if rec.get("status") is not None:
                existing_obj["status"] = rec.get("status")
            if rec.get("server") and not existing_obj.get("server"):
                existing_obj["server"] = rec.get("server")
            if rec.get("title") and not existing_obj.get("title"):
                existing_obj["title"] = rec["title"]
            if host and not existing_obj.get("host"):
                existing_obj["host"] = host
        else:
            new_cnt += 1
            new_obj = {
                "url": url,
                "host": host,
                "status": rec.get("status"),
                "server": rec.get("server", ""),
                "title": rec.get("title", ""),
                "priority": _rank_host(host)[0] if host else "P3",
                "source": "exec",
                "sources": ["exec"],
                "added_at": datetime.datetime.now().isoformat(),
            }
            endpoints.append(new_obj)
            existing_by_url[key] = new_obj

    if new_cnt > 0 or known_cnt > 0:
        ep_file.write_text(json.dumps(endpoints, indent=2), encoding="utf-8")

    # 4. Sync detected technologies into .engagement/technologies.json
    tech_candidates: set[str] = set()

    top_tech = meta.get("technologies") or meta.get("tech") or execution_result.get("technologies") or execution_result.get("tech")
    if top_tech and isinstance(top_tech, (list, set, tuple)):
        for t in top_tech:
            if t and isinstance(t, str):
                tech_candidates.add(t.strip())

    if live_hosts and isinstance(live_hosts, (list, set, tuple)):
        for item in live_hosts:
            if isinstance(item, dict):
                h_techs = item.get("technologies") or item.get("tech") or []
                if isinstance(h_techs, (list, set, tuple)):
                    for t in h_techs:
                        if t and isinstance(t, str):
                            tech_candidates.add(t.strip())

    if ep_list and isinstance(ep_list, (list, set, tuple)):
        for item in ep_list:
            if isinstance(item, dict):
                e_techs = item.get("technologies") or item.get("tech") or []
                if isinstance(e_techs, (list, set, tuple)):
                    for t in e_techs:
                        if t and isinstance(t, str):
                            tech_candidates.add(t.strip())

    if tech_candidates:
        t_file = d / "technologies.json"
        existing_tech: dict[str, Any] = {}
        if t_file.exists():
            try:
                existing_tech = json.loads(t_file.read_text(encoding="utf-8"))
            except Exception:
                existing_tech = {}
        if not isinstance(existing_tech, dict):
            existing_tech = {}

        frameworks = set(existing_tech.get("frameworks", []))
        for t in tech_candidates:
            frameworks.add(t)
        existing_tech["frameworks"] = sorted(list(frameworks))
        t_file.write_text(json.dumps(existing_tech, indent=2), encoding="utf-8")

    return new_cnt, known_cnt


def run_recon(
    target: str,
    out_dir: str | Path | None = None,
    proxy: str | None = None,
    burp: bool = False,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    from nyx.execution.policy import normalize_target
    target = normalize_target(target)
    clone_mode = (REPO_ROOT / "skills").is_dir()
    recon_root = (
        Path(out_dir).resolve()
        if out_dir
        else (REPO_ROOT / "recon" if clone_mode else Path.cwd() / "recon")
    )
    
    target_clean = re.sub(r"^https?://", "", target).rstrip("/")
    target_folder = re.sub(r'[:/\\?*|"<>]', '_', target_clean)
    target_host = target_clean.split(":")[0].split("/")[0]

    target_dir = recon_root / target_folder
    resolved_path = target_dir.resolve()
    safe_path = recon_root.resolve()
    if resolved_path != safe_path and safe_path not in resolved_path.parents:
        return {"status": "error", "message": f"invalid target: {target}"}

    target_dir = resolved_path
    target_dir.mkdir(parents=True, exist_ok=True)

    from nyx.recon.tracker import active_recon_tracker
    active_recon_tracker.start(target=target, initial_phase="subdomain_enum", message=f"Starting reconnaissance for {target}...")

    logger.info("[RECON] Starting reconnaissance for target: %s", target)

    if proxy or burp:
        proxy_url = proxy or (detect_burp() or "http://127.0.0.1:8080")
        configure_http_proxy(proxy_url, insecure=True)

    logger.info("[RECON] Subdomain enumeration started for host: %s", target_host)
    active_recon_tracker.update_phase("subdomain_enum", f"Enumerating subdomains for {target_host}...")
    subs = set()
    subs |= recon_subdomains_via_crtsh(target_host)
    sf = recon_subdomains_via_subfinder(target_host)
    if sf:
        subs |= sf
    if not subs:
        subs.add(target_host)
    subs.add(target_host)

    logger.info("[RECON] Discovered %d subdomains for %s: %s", len(subs), target_host, ", ".join(sorted(subs)[:5]))

    (target_dir / "subdomains.txt").write_text(
        "\n".join(sorted(subs)) + "\n", encoding="utf-8"
    )

    logger.info("[RECON] DNS resolution started for %d subdomains", len(subs))
    active_recon_tracker.update_phase("dns_resolution", f"Resolving DNS for {len(subs)} subdomains...", subdomains_count=len(subs))
    resolved = {}
    for s in sorted(subs):
        ips = recon_resolve(s)
        if ips:
            resolved[s] = ips
    logger.info("[RECON] Resolved %d live hostnames", len(resolved))

    (target_dir / "resolved.txt").write_text(
        "\n".join(f"{h}|{','.join(ips)}" for h, ips in sorted(resolved.items()))
        + "\n",
        encoding="utf-8",
    )

    hosts_to_probe = set(resolved.keys())
    if ":" in target_clean or "/" in target_clean:
        hosts_to_probe.add(target_clean)
    if target.startswith("http://") or target.startswith("https://"):
        hosts_to_probe.add(target)

    logger.info("[RECON] HTTP probing started for %d endpoints", len(hosts_to_probe))
    active_recon_tracker.update_phase("http_probing", f"Probing HTTP services across {len(hosts_to_probe)} endpoints...", resolved_count=len(resolved))
    live = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(recon_http_probe, h): h for h in hosts_to_probe}
        for f in as_completed(futures):
            host = futures[f]
            rec = f.result()
            if rec:
                rec["host"] = host
                live.append(rec)
    logger.info("[RECON] Probing identified %d live HTTP services", len(live))

    (target_dir / "live-hosts.json").write_text(
        json.dumps(live, indent=2), encoding="utf-8"
    )

    # Content & unlinked path discovery sub-stage
    live_urls = [r["url"] for r in live if r.get("url")]
    target_full_url = target if (target.startswith("http://") or target.startswith("https://")) else f"https://{target_clean}"
    if target_full_url not in live_urls and target_full_url.rstrip("/") not in [u.rstrip("/") for u in live_urls]:
        live_urls.insert(0, target_full_url)
    elif target_full_url in live_urls:
        live_urls.remove(target_full_url)
        live_urls.insert(0, target_full_url)

    if not live_urls and resolved:
        live_urls = [f"https://{h}" for h in sorted(resolved)]
    if not live_urls:
        live_urls = [target_full_url]

    logger.info("[RECON] Content & route discovery started on %d live endpoints", len(live_urls))
    active_recon_tracker.update_phase("content_discovery", f"Discovering routes & parameters across {len(live_urls)} live endpoints...", live_count=len(live))

    meta_map = {}
    for r in live:
        if isinstance(r, dict) and r.get("url"):
            meta_map[r["url"].split("#")[0].rstrip("/")] = r

    def _on_cd_progress(idx: int, total: int, base_url: str, found_cnt: int, status_note: str = ""):
        parsed_host = urllib.parse.urlparse(base_url).hostname or base_url
        note = f" [{status_note}]" if status_note else ""
        active_recon_tracker.update_phase(
            "content_discovery",
            f"[{idx + 1}/{total}] Content discovery on {parsed_host}{note} ({found_cnt} paths found)...",
            content_discovery_current=idx + 1,
            content_discovery_total=total,
            content_discovered_count=found_cnt,
            live_count=len(live),
        )

    content_discovered = run_content_discovery(
        live_urls,
        endpoint_metadata=meta_map,
        progress_callback=_on_cd_progress,
    )
    logger.info("[RECON] Content discovery mapped %d paths/parameters", len(content_discovered))

    (target_dir / "content-discovery.json").write_text(
        json.dumps(content_discovered, indent=2), encoding="utf-8"
    )

    summary_path = target_dir / "RECON_SUMMARY.md"
    write_recon_summary(target, subs, resolved, live, summary_path, content_discovered=content_discovered)

    manifest = build_manifest(target, subs, resolved, live, content_discovered=content_discovered)
    manifest_path = target_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    active_recon_tracker.update_phase("syncing", f"Syncing {len(live) + len(resolved) + len(content_discovered)} assets into engagement memory...", content_discovery_count=len(content_discovered))
    tot_disc, new_cnt, known_cnt = sync_recon_to_engagement(
        target, subs, resolved, live, content_discovered=content_discovered, base_dir=base_dir
    )
    logger.info("[DONE] Reconnaissance complete for %s — %d endpoints processed (%d new, %d already known)", target, tot_disc, new_cnt, known_cnt)

    exec_id: str | None = None
    try:
        from nyx.execution.engine import ExecutionEngine
        from nyx.models.execution import ExecutionResult, ExecutionStatus
        import uuid

        exec_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        engine = ExecutionEngine(base_dir=base_dir)
        exec_result = ExecutionResult(
            execution_id=exec_id,
            tool_name="nyx-recon",
            target=target,
            status=ExecutionStatus.COMPLETED.value,
            exit_code=0,
            stdout=f"Passive recon harvested {tot_disc} endpoints ({new_cnt} new, {known_cnt} existing).",
            stderr="",
            artifacts={
                "manifest_path": str(manifest_path),
                "summary_path": str(summary_path),
                "endpoints_count": tot_disc,
                "subdomains_count": len(subs),
                "resolved_count": len(resolved),
                "live_count": len(live),
            },
            execution_class="PASSIVE_READ",
            authorized=True,
            scope_status="CONFIGURED",
        )
        engine.log_execution_to_db(exec_result)
    except Exception:
        pass

    final_res = {
        "status": "success",
        "target": target,
        "execution_id": exec_id,
        "out_dir": str(target_dir),
        "subdomains_count": len(subs),
        "resolved_count": len(resolved),
        "live_count": len(live),
        "content_discovery_count": len(content_discovered),
        "content_discovered": content_discovered,
        "summary_path": str(summary_path),
        "manifest_path": str(manifest_path),
        "sync_total": tot_disc,
        "sync_new": new_cnt,
        "sync_known": known_cnt,
    }
    active_recon_tracker.complete(final_res)
    return final_res


# Function aliases for backward compatibility and test suites
run = run_recon
run_intelligence = run_recon_intelligence