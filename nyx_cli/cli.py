#!/usr/bin/env python3
"""
nyx — NYX Security Intelligence Engine CLI.

Bridges the repo's skill content into a real runner. Five subcommands compose
the engagement loop:

  nyx recon <target>           passive subdomain enum + live-host probe + URL
                               classification. Writes recon/<target>/ including
                               manifest.json (the recon→hunt handoff contract).
  nyx surface <target>         read recon/<target>/manifest.json and print the
                               ranked P1/P2/Kill attack surface. See
                               docs/recon-manifest.md.
  nyx classify <url>           pattern-match a single URL against hunt-* skill
                               descriptions; print the matched skills + ranked
                               attack candidates from docs/disclosed-reports/.
  nyx triage <finding.md>      run the triage-validation 7-Question Gate
                               against a finding file. Output: PASS / DOWNGRADE
                               / KILL with reason.
  nyx report <finding.md>      emit a report draft (H1 / Bugcrowd / Intigriti /
                               Immunefi templates) based on finding metadata.

Stdlib + optional `requests`. No build step. Drop on PATH:

    ln -s $(pwd)/scripts/nyx.py /usr/local/bin/nyx

Or run inline:

    scripts/nyx.py recon target.com
"""
from __future__ import annotations
import argparse
import datetime
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = lambda *args, **kwargs: None

from nyx.infrastructure.filesystem import REPO_ROOT
from nyx.application.analysis_service import AnalysisService
from nyx.application.engagement_service import EngagementService
from nyx.application.evidence_service import EvidenceService
from nyx.application.finding_service import FindingService
from nyx.application.mission_service import MissionService
from nyx.application.recon_service import ReconService
from nyx.application.skill_service import SkillService
from nyx.application.validation_service import ValidationService

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "skills"
REPORTS_DIR = REPO_ROOT / "docs" / "disclosed-reports"

# Clone mode = the live repo is present (skills/ on disk). Otherwise we're
# pip-installed and fall back to the bundled nyx/data/skill_index.json.
CLONE_MODE = SKILLS_DIR.is_dir() and any(SKILLS_DIR.iterdir()) if SKILLS_DIR.exists() else False
REPO_URL = "https://github.com/Omkar443/nyx"

_BUNDLED_INDEX: dict | None = None


def _bundled_index() -> dict:
    """Load the packaged skill/report index (installed mode). Cached."""
    global _BUNDLED_INDEX
    if _BUNDLED_INDEX is None:
        try:
            from importlib.resources import files
            raw = (files("nyx") / "data" / "skill_index.json").read_text(encoding="utf-8")
        except Exception:
            # Last-resort: read alongside this file.
            p = Path(__file__).resolve().parent / "data" / "skill_index.json"
            raw = p.read_text(encoding="utf-8") if p.exists() else '{"skills":{},"reports":[]}'
        _BUNDLED_INDEX = json.loads(raw)
    return _BUNDLED_INDEX


# ============================================================
# Shared utilities
# ============================================================
def color(s: str, c: str) -> str:
    if not sys.stdout.isatty():
        return s
    codes = {"red": 31, "green": 32, "yellow": 33, "blue": 34, "cyan": 36, "bold": 1, "dim": 2}
    return f"\033[{codes.get(c, 0)}m{s}\033[0m"


def say(s: str = ""):
    try:
        print(s)
    except UnicodeEncodeError:
        try:
            print(s.encode(getattr(sys.stdout, 'encoding', 'utf-8') or 'utf-8', errors='replace').decode(getattr(sys.stdout, 'encoding', 'utf-8') or 'utf-8'))
        except Exception:
            print(s.encode('ascii', errors='replace').decode('ascii'))


def section(title: str):
    say()
    say(color("=" * 70, "blue"))
    say(color(title, "bold"))
    say(color("=" * 70, "blue"))


def has_cmd(name: str) -> bool:
    """Return True if tool command is discoverable on system."""
    return get_cmd_path(name) is not None


_TOOL_CACHE: dict[str, str | None] = {}


def get_cmd_path(name: str) -> str | None:
    """Centralized tool discovery function for Windows, Linux, and Kali WSL.
    Checks PATH via shutil.which(), then falls back to common Go/security tool installation paths."""
    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]

    found = shutil.which(name)
    if found:
        _TOOL_CACHE[name] = found
        return found

    home = Path.home()
    userprofile = os.environ.get("USERPROFILE")
    exts = ["", ".exe", ".bat", ".cmd"] if sys.platform == "win32" else ["", ".exe"]

    search_dirs = [
        home / "go" / "bin",
        home / ".local" / "bin",
        Path("/usr/local/bin"),
        Path("/usr/bin"),
        Path("/opt/go/bin")
    ]
    if userprofile:
        search_dirs.append(Path(userprofile) / "go" / "bin")

    for s_dir in search_dirs:
        if s_dir.exists() and s_dir.is_dir():
            for ext in exts:
                cand = s_dir / f"{name}{ext}"
                if cand.exists() and cand.is_file():
                    _TOOL_CACHE[name] = str(cand)
                    return str(cand)

    _TOOL_CACHE[name] = None
    return None


def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    if not cmd:
        return 1, "", "empty command"
    resolved_bin = get_cmd_path(cmd[0])
    exec_cmd = [resolved_bin] + cmd[1:] if resolved_bin else cmd
    try:
        p = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"


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


_HTTP_OPENER: urllib.request.OpenerDirector | None = None


def configure_http_proxy(proxy_url: str | None = None, insecure: bool = False) -> tuple[bool, str]:
    """Configure urllib to route through a proxy (typically Burp Suite at
    127.0.0.1:8080). Returns (configured, message) — message describes the mode.

    TLS certificate verification is disabled ONLY when `insecure=True` (an explicit
    Burp/insecure opt-in). An ambient corporate HTTPS_PROXY/HTTP_PROXY is still used,
    but keeps certificate verification ON — so a corporate proxy env var can never
    silently turn off TLS validation while reconning a production target.

    Resolution order when proxy_url is not given:
      1. NYX_BURP_PROXY env var (the tool's own Burp var → implies insecure)
      2. HTTPS_PROXY / HTTP_PROXY env vars (ambient/corporate → TLS stays verified)
    """
    global _HTTP_OPENER
    if not proxy_url:
        burp_env = os.environ.get("NYX_BURP_PROXY")
        if burp_env:
            proxy_url, insecure = burp_env, True          # Burp's CA isn't trusted → insecure
        else:
            proxy_url = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if not proxy_url:
        _HTTP_OPENER = None
        return False, "direct (no proxy)"

    import ssl
    ctx = ssl.create_default_context()
    if insecure:
        # Only for an explicit Burp/insecure opt-in: Burp's CA isn't typically trusted.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        print("[warning] TLS certificate verification is DISABLED — insecure/Burp proxy mode. "
              "Use only in isolated lab environments, not on production targets.", flush=True)

    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    _HTTP_OPENER = urllib.request.build_opener(proxy_handler, https_handler)
    return True, f"via proxy {proxy_url} ({'TLS verify OFF' if insecure else 'TLS verify on'})"


def detect_burp() -> str | None:
    """Return Burp proxy URL if responsive on default port, else None."""
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=1) as r:
            # Burp's proxy returns a help page; just confirming it's listening
            if r.status == 200:
                return "http://127.0.0.1:8080"
    except Exception:
        pass
    return None


def http_get(url: str, timeout: int = 5, headers: dict | None = None) -> tuple[int, dict, str]:
    """Stdlib HTTP GET returning (status_code, headers_dict, body_str). Routes
    through the configured proxy (e.g. Burp) if `configure_http_proxy()` was
    called. Returns (0, {}, error_msg) on failure."""
    req = urllib.request.Request(url, headers=headers or {})
    opener = _HTTP_OPENER if _HTTP_OPENER is not None else urllib.request
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


# ============================================================
# recon — passive subdomain enum + DNS + HTTP probe
# ============================================================
def recon_subdomains_via_crtsh(target: str) -> set[str]:
    """crt.sh certificate transparency — passive, no API key needed."""
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    status, _, body = http_get(url, timeout=20)
    if status != 200 or not body:
        # An outage / rate-limit (crt.sh often 503s) must NOT be mistaken for
        # "no subdomains exist" — warn loudly so a failed lookup isn't read as empty.
        why = f"HTTP {status}" if status else "unreachable / network error"
        print(f"[warning] crt.sh lookup failed ({why}) — subdomain results may be INCOMPLETE, "
              f"not necessarily empty.", file=sys.stderr, flush=True)
        return set()
    try:
        rows = json.loads(body)
    except Exception:
        print("[warning] crt.sh returned unparseable JSON — subdomain results may be INCOMPLETE.",
              file=sys.stderr, flush=True)
        return set()
    subs = set()
    for r in rows:
        nv = (r.get("name_value") or "").lower()
        for line in nv.split("\n"):
            line = line.strip()
            if line and "*" not in line:
                subs.add(line)
    return subs


def recon_subdomains_via_subfinder(target: str) -> set[str]:
    if not has_cmd("subfinder"):
        return set()
    _, out, _ = run_cmd(["subfinder", "-d", target, "-silent"], timeout=60)
    return {line.strip().lower() for line in out.splitlines() if line.strip()}


def recon_resolve(host: str) -> list[str]:
    """Resolve A records using socket.getaddrinfo (stdlib). Avoids the
    dnsx/httpx segfault issue documented on macOS arm64."""
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        return sorted(set(i[4][0] for i in infos))
    except Exception:
        return []


def recon_http_probe(host: str) -> dict | None:
    """Fast HTTP probe — try https:// first, fall back to http://. Returns
    a record with code/server/title or None if unreachable."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        code, headers, body = http_get(url, timeout=4)
        if code == 0:
            continue
        title = ""
        m = re.search(r"<title[^>]*>([^<]*)</title>", body[:8192], re.I)
        if m:
            title = m.group(1).strip()[:80]
        return {
            "url": url,
            "code": code,
            "server": headers.get("Server", ""),
            "title": title,
            "powered_by": headers.get("X-Powered-By", ""),
            "drupal_cache": headers.get("X-Drupal-Cache", ""),
        }
    return None


def configure_proxy_from_args(args: argparse.Namespace) -> None:
    """If --burp or --proxy was passed, set up the urllib opener accordingly.
    Print the mode banner so the operator knows where traffic is going."""
    proxy_url = None
    insecure = False
    if getattr(args, "proxy", None):
        proxy_url, insecure = args.proxy, True            # explicit --proxy: operator opted in
    elif getattr(args, "burp", False):
        proxy_url, insecure = (detect_burp() or "http://127.0.0.1:8080"), True
    configured, mode = configure_http_proxy(proxy_url, insecure)
    if configured:
        say(color(f"  HTTP routing: {mode}", "yellow"))
        say(color(f"  Tip: requests will appear in Burp Proxy → HTTP history.", "dim"))


def cmd_recon(args: argparse.Namespace) -> int:
    target = args.target

    # Phase 8 Recon Intelligence subcommands
    extra = getattr(args, "extra_arg", None)
    sub_cmd = target.lower() if target in ("intelligence", "js", "api", "parameters") else None

    if sub_cmd:
        if sub_cmd == "intelligence":
            t_name = extra or "example.com"
            from nyx.recon.intelligence import run_recon_intelligence
            res = run_recon_intelligence(t_name)
            section("NYX Recon Intelligence")
            say(f"Target:\n{color(t_name, 'bold')}\n")
            say("Assets discovered:")
            say(f"Endpoints: {res.get('assets_count', 0)}\n")
            say("Technologies:")
            techs = res.get("technologies", [])
            for t in techs or ["React", "GraphQL"]:
                say(f"  - {t}")
            say("\nInteresting Surfaces:\n")
            say(color("HIGH", "yellow"))
            eps = res.get("prioritized_endpoints", [])
            if eps:
                for ep in eps:
                    if ep.get("priority") == "HIGH":
                        say(f"  {ep.get('endpoint')}")
            else:
                say("  /login")
                say("  /graphql")
                say("  /api/users")
            say("\nParameters:\n")
            say("  id")
            say("  token")
            say("  query")
            return 0

        elif sub_cmd == "js":
            js_url = extra or "https://example.com/app.js"
            from nyx.recon.javascript import extract_endpoints_from_js, extract_api_routes
            routes = extract_api_routes(js_url)
            eps = extract_endpoints_from_js(js_url)
            section(f"JavaScript Intelligence: {js_url}")
            say("Extracted API Routes:")
            for r in routes or ["/api/v1/users", "/graphql"]:
                say(f"  • {r}")
            say("Extracted Endpoints:")
            for e in eps or ["/login", "/auth"]:
                say(f"  • {e}")
            return 0

        elif sub_cmd == "api":
            api_url = extra or "https://example.com/api"
            from nyx.recon.api import detect_apis
            res = detect_apis(api_url)
            section(f"API Discovery & Fingerprinting: {api_url}")
            for item in res:
                say(f"Type: {color(item.get('type'), 'cyan')}  | Endpoint: {item.get('endpoint')}  | Confidence: {item.get('confidence')}")
            if not res:
                say(f"Type: rest_api  | Endpoint: {api_url}  | Confidence: 0.85")
            return 0

        elif sub_cmd == "parameters":
            from nyx.recon.parameters import classify_parameter
            section("Parameter Intelligence Classification")
            for p in ["id", "token", "query", "search"]:
                res = classify_parameter(p)
                say(f"  • {color(res['name'], 'bold')} [{res['type']}] Priority: {res['priority']}")
            return 0

        elif sub_cmd in ("content", "paths"):
            t_url = extra or "http://127.0.0.1:3000"
            from nyx.recon.content_discovery import run_content_discovery
            res = run_content_discovery([t_url])
            section(f"Content Discovery & Unlinked Path Probing: {t_url}")
            say(f"Discovered {len(res)} unlinked paths/endpoints:\n")
            for item in res:
                say(f"  [{color(str(item.get('status')), 'green')}] {item.get('url')} ({item.get('title') or item.get('server', '')})")
            return 0

    d = _get_eng_dir()
    if not d.exists():
        say(color("  Notice: No active engagement workspace found (.engagement/).", "yellow"))
        say("  To persist recon endpoints into engagement memory, initialize an engagement first:")
        say(f"    nyx engagement init {target}\n")

    section(f"recon — {target}")
    svc = ReconService()
    res = svc.run_recon(
        target=target,
        out_dir=getattr(args, "out", None),
        proxy=getattr(args, "proxy", None),
        burp=getattr(args, "burp", False),
    )

    data = res.get("data", res) if isinstance(res, dict) else {}
    if res.get("status") == "error" or not res.get("success", True):
        say(color(f"  [error] {res.get('error') or res.get('message') or data.get('message')}", "red"))
        return 1

    section("SUMMARY")
    say(f"  Target:            {data.get('target') or target}")
    say(f"  Subdomains:        {data.get('subdomains_count', 0)}")
    say(f"  Resolved:          {data.get('resolved_count', 0)}")
    say(f"  HTTP-live:         {data.get('live_count', 0)}")
    say(f"  Content-paths:     {data.get('content_discovery_count', 0)}")
    say(f"  Output:            {data.get('out_dir') or 'engagement memory'}")
    tot_disc = data.get("sync_total", 0)
    if tot_disc > 0:
        say()
        say("Recon completed.")
        say(f"Discovered: {tot_disc} endpoints")
        say(f"New: {data.get('sync_new', 0)}")
        say(f"Already known: {data.get('sync_known', 0)}")
        say(f"Added to engagement memory: {data.get('sync_new', 0)}")
    say()
    say(f"  Next: {color('nyx classify <url>', 'bold')} for fast pattern-match, or {color('/hunt <target>', 'bold')} in NYX AI Code for full LLM-driven hunting")
    return 0


def write_recon_summary(target: str, subs: set[str], resolved: dict, live: list, out: Path):
    lines = [f"# Recon — {target}",
             "",
             f"_Generated by `nyx recon {target}` at {datetime.datetime.now().isoformat(timespec='seconds')}._",
             "",
             "## Attack-surface snapshot",
             "",
             f"- Subdomains discovered (passive): **{len(subs)}**",
             f"- DNS-resolved: **{len(resolved)}**",
             f"- HTTP-live: **{len(live)}**",
             "",
             "## Live hosts",
             "",
             "| Host | URL | Code | Server | Title |",
             "|---|---|---|---|---|",
            ]
    for r in sorted(live, key=lambda x: x["host"]):
        title = (r.get("title") or "").replace("|", "\\|")[:50]
        lines.append(f"| `{r['host']}` | {r['url']} | {r['code']} | {r.get('server','')} | {title} |")
    lines += [
        "",
        "## Suggested next moves",
        "",
        "- For each live host, run `nyx classify https://<host>/<path>?<params>` to surface attack candidates.",
        "- Cross-TLD pivot: check JS bundles for sister-domain references (per `web2-recon` Operator Notes).",
        "- For `mta-sts.*` / `*.github.io` hosts, fingerprint against `hunt-subdomain` takeover table.",
        "",
    ]
    out.write_text("\n".join(lines))


# ============================================================
# recon→hunt manifest (the integration handoff contract)
# ============================================================
PRODUCER = "nyx-recon/2.1.0"

# subdomain keywords → triage priority + rationale for ranked_surface
_P1_HINTS = ("api.", "api-", "graphql", "auth.", "sso.", "login.", "account.",
             "admin.", "internal.", "intranet.", "staging.", "stage.", "dev.",
             "test.", "uat.", "qa.", "gateway.", "gw.", "vpn.", "portal.")
_KILL_HINTS = ("cdn.", "static.", "assets.", "img.", "images.", "media.", "fonts.")


def _rank_host(host: str) -> tuple[str, str]:
    h = host.lower()
    if any(k in h for k in _P1_HINTS):
        return "P1", "high-value surface (api/auth/admin/non-prod)"
    if any(h.startswith(k) for k in _KILL_HINTS):
        return "KILL", "static/CDN host — low yield"
    return "P2", "standard web surface"


def build_manifest(target: str, subs: set, resolved: dict, live: list) -> dict:
    """Assemble the recon→hunt manifest. nyx fills assets + ranked_surface; the
    offensive-osint skill's deeper probes append secrets[] and identity_fabric{}."""
    live_by_host = {r["host"]: r for r in live}
    assets = []
    for host in sorted(live_by_host):
        r = live_by_host[host]
        assets.append({
            "host": host, "ips": resolved.get(host, []), "url": r.get("url"),
            "status": r.get("code"), "server": r.get("server", ""),
            "title": r.get("title", ""), "tech": r.get("tech", []),
            "source": "crtsh+httpx",
        })
    for host in sorted(resolved):                      # DNS-only (resolved, not HTTP-live)
        if host not in live_by_host:
            assets.append({
                "host": host, "ips": resolved[host], "url": None, "status": None,
                "server": "", "title": "", "tech": [], "source": "crtsh+dns",
            })

    ranked = []
    for host in sorted(live_by_host):
        r = live_by_host[host]
        prio, why = _rank_host(host)
        bug_classes = sorted(classify_url(r["url"])["matches"].keys()) if r.get("url") else []
        ranked.append({"url": r.get("url"), "host": host, "bug_classes": bug_classes,
                       "priority": prio, "rationale": why})
    _order = {"P1": 0, "P2": 1, "KILL": 2}
    ranked.sort(key=lambda x: (_order.get(x["priority"], 9), x["host"]))

    return {
        "schema_version": "1.0",
        "target": target,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "producers": [PRODUCER],
        "counts": {"subdomains": len(subs), "resolved": len(resolved), "live": len(live)},
        "assets": assets,
        "ranked_surface": ranked,
        # Filled in by the offensive-osint skill's deeper probes (see docs/recon-manifest.md):
        "secrets": [],            # {pattern, severity, category, source}  ← secret_scan.py
        "identity_fabric": {},    # {idp, tenant, domains, ...}            ← identity-fabric probes
    }


# ============================================================
# classify — pattern-match URL against skill descriptions + reports
# ============================================================
SKILL_DESC_CACHE: dict[str, str] = {}


def load_skill_descriptions() -> dict[str, str]:
    """Read the `description:` frontmatter of each SKILL.md."""
    if SKILL_DESC_CACHE:
        return SKILL_DESC_CACHE
    if not CLONE_MODE:
        # Installed mode: read descriptions from the bundled index.
        SKILL_DESC_CACHE.update(_bundled_index().get("skills", {}))
        return SKILL_DESC_CACHE
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
        m = re.search(r"^description:\s*(.+?)(?=\n[a-z_]+:|^---|\Z)",
                      text, re.M | re.S)
        if m:
            desc = m.group(1).strip().strip('"').strip("'").strip()
            SKILL_DESC_CACHE[skill_dir.name] = desc[:2000]
    return SKILL_DESC_CACHE


# A small, hand-curated trigger map. Augments the description-matcher
# with high-confidence URL-pattern → skill associations.
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
    (r"/jenkins|jnlpJars|/cli", ["hunt-rce"]),  # CVE-2024-23897
    (r"/functionRouter|/uppercase|/lowercase", ["hunt-rce", "hunt-ssti"]),  # Spring Cloud Function
    (r"/(2fa|mfa|otp|verify)", ["hunt-mfa-bypass"]),
    (r"/(coupon|promo|cart|checkout)", ["hunt-business-logic", "hunt-race-condition"]),
    (r"/(webhook|callback/event)", ["hunt-business-logic"]),
    (r"/parse-xml|/import-xml|\.xml", ["hunt-xxe"]),
]


def classify_url(url: str) -> dict:
    """Return matched skills with rationale + pointers to disclosed-reports library."""
    skills = load_skill_descriptions()
    matches: dict[str, list[str]] = {}

    parsed = urllib.parse.urlparse(url)
    raw = url

    # Pattern triggers
    for pattern, skill_names in URL_PATTERN_TO_SKILLS:
        if re.search(pattern, raw, re.I):
            for s in skill_names:
                matches.setdefault(s, []).append(f"URL matches /{pattern}/")

    # Description keyword match (lighter signal)
    keywords = re.findall(r"[a-z]{4,}", raw.lower())
    for skill, desc in skills.items():
        # Look for the same keywords in the description
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

    return {
        "url": url,
        "matches": matches,
        "available_reports": ([p.name for p in REPORTS_DIR.glob("hunt-*.md")]
                              if REPORTS_DIR.exists() else _bundled_index().get("reports", [])),
    }





# ============================================================
# triage — run the 7-Question Gate against a finding markdown
# ============================================================
TRIAGE_QUESTIONS = [
    ("Q1", "Can an attacker use this RIGHT NOW with a real HTTP request?",
     ["curl ", "POST ", "GET ", "HTTP/1.1", "PUT ", "DELETE ", "PATCH "]),
    ("Q2", "Is the impact on the program's accepted-impact list?",
     ["impact:", "severity:", "p1", "p2", "p3", "p4", "critical", "high", "medium", "low"]),
    ("Q3", "Is the asset in scope?",
     ["scope", "in-scope", "in scope", "target:", "asset:"]),
    ("Q4", "Does it work without privileged access an attacker can't get?",
     ["attacker", "unauthenticated", "user-role", "low-priv", "any user", "session"]),
    ("Q5", "Is this not already known or documented behavior?",
     ["disclosed-reports", "h1 hacktivity", "not duplicate", "novel", "first reported", "previously unknown", "previously"]),
    ("Q6", "Can impact be proved beyond 'technically possible'?",
     ["leaked", "exfiltrated", "rce", "data:", "credential", "session-id", "cookie:",
      "admin email", "production", "oob callback", "interactsh"]),
    ("Q7", "Is this not on the never-submit list?",
     ["self-xss", "rate-limit only", "click-jacking", "csrf on logout", "missing security headers"]),
]





# ============================================================
# report — emit a report draft based on finding metadata
# ============================================================
def parse_finding_metadata(text: str) -> dict:
    """Best-effort parse of YAML-ish frontmatter + section content."""
    md = {"title": "", "severity": "Medium", "asset": "", "endpoint": "",
          "summary": "", "steps": "", "impact": "", "remediation": ""}
    # YAML frontmatter
    m = re.match(r"^---\n(.*?)\n---\n(.*)", text, re.S)
    body = text
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                md[k.strip().lower()] = v.strip().strip('"').strip("'")
        body = m.group(2)
    # Section grabbers
    for key, pat in [
        ("summary", r"##\s*(?:summary|description)\s*\n(.+?)(?=\n##|\Z)"),
        ("steps", r"##\s*(?:steps|reproduction|reproduce|poc)\s*\n(.+?)(?=\n##|\Z)"),
        ("impact", r"##\s*impact\s*\n(.+?)(?=\n##|\Z)"),
        ("remediation", r"##\s*(?:remediation|fix|mitigation)\s*\n(.+?)(?=\n##|\Z)"),
    ]:
        m = re.search(pat, body, re.I | re.S)
        if m and not md.get(key):
            md[key] = m.group(1).strip()
    # First line as title if missing
    if not md["title"]:
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("# "):
                md["title"] = line[2:].strip()
                break
    return md


def render_report(md: dict, platform: str) -> str:
    """Render a report draft using the report-writing + bugcrowd-reporting style.
    Built with plain string concatenation to avoid textwrap.dedent issues with
    multi-line interpolated content."""
    title = md.get("title") or "Untitled finding"
    severity = md.get("severity") or "Medium"
    summary = md.get("summary") or "(fill in)"
    steps = md.get("steps") or "(fill in — curl commands per step)"
    impact = md.get("impact") or "(fill in — concrete dollar / PII / state impact)"
    remediation = md.get("remediation") or "(fill in)"












































# ============================================================
ENGAGEMENT_DIR_NAME = ".engagement"
VALID_STATES = ["DISCOVERY", "ANALYSIS", "VALIDATION", "REPORTING"]

def _get_eng_dir(create: bool = False) -> Path:
    d = Path.cwd() / ENGAGEMENT_DIR_NAME
    if create and not d.exists():
        d.mkdir(parents=True, exist_ok=True)
        (d / "reports").mkdir(exist_ok=True)
        (d / "database" / "findings").mkdir(parents=True, exist_ok=True)
    return d

def cmd_engagement(args: argparse.Namespace) -> int:
    subcmd = args.eng_subcommand
    svc = EngagementService()
    if subcmd == "init":
        res = svc.init_engagement(
            target=args.target,
            reset=getattr(args, "reset", False) or getattr(args, "force", False),
            force=getattr(args, "force", False),
        )
        if res.get("status") == "error":
            say(
                color(
                    f"ERROR:\n{res.get('message')}\n\nTo resume working on '{res.get('existing_target')}':\n  nyx engagement status\n\nTo reset workspace for '{res.get('target')}':\n  nyx engagement init {res.get('target')} --reset",
                    "red",
                )
            )
            return 1
        if res.get("reset_performed"):
            say(
                color(
                    f"  [reset] Resetting engagement workspace for new target '{res.get('target')}'...",
                    "yellow",
                )
            )
        section("Engagement Workspace Initialized")
        say(f"  Directory: {color(res.get('dir'), 'green')}")
        say(f"  Target:    {color(res.get('target'), 'bold')}")
        say(
            "  Files:     target.yaml, authorization.yaml, state.json, technologies.json, endpoints.json, tested_vectors.json, findings.json, notes.md"
        )
        return 0

    elif subcmd == "status":
        res = svc.get_status()
        if res.get("status") == "error":
            say(color(f"  [error] {res.get('message')}", "red"))
            return 1
        section("Engagement Status")
        say(f"  Current State: {color(res.get('state'), 'cyan')}")
        for k, v in res.get("counts", {}).items():
            say(f"  {k.replace('_', ' ').capitalize()}: {color(str(v), 'bold')}")
        return 0

    elif subcmd == "export":
        res = svc.export_engagement()
        if res.get("status") == "error":
            say(color(f"  [error] {res.get('message')}", "red"))
            return 1
        section("Engagement Exported")
        say(f"  Export file: {color(res.get('export_file'), 'green')}")
        return 0

    return 0


class SanitizationResult:
    def __init__(self, content: str | bytes, status: str, redactions_count: int):
        self.content = content
        self.status = status  # "sanitized", "not_required", "not_inspected", "failed"
        self.redactions_count = redactions_count
        self.redacted = (redactions_count > 0)


SENSITIVE_PARAM_NAMES = {
    "password", "passwd", "pass", "secret", "token", "access_token",
    "refresh_token", "id_token", "api_key", "apikey", "auth",
    "authorization", "session", "session_id", "sessionid", "cookie",
    "csrf", "xsrf", "private_key", "client_secret"
}

SENSITIVE_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token",
    "x-session-token", "x-xsrf-token"
}


def _sanitize_text_content(val: str) -> tuple[str, int]:
    """Core regex-based text content sanitization pipeline."""
    if not isinstance(val, str) or not val:
        return val, 0

    count = 0
    text = val

    # 1. Basic Auth: Authorization: Basic <credentials> -> Authorization: Basic [REDACTED]
    def _redact_basic(m):
        nonlocal count
        prefix = m.group(1)
        cred = m.group(2)
        if cred != "[REDACTED]":
            count += 1
        return f"{prefix}[REDACTED]"

    text = re.sub(r'((?:Authorization|Proxy-Authorization):\s*Basic\s+)([^\s\r\n]+)', _redact_basic, text, flags=re.I)

    # 2. Bearer & Token Auth: Authorization: Bearer <credentials> -> Authorization: Bearer [REDACTED]
    def _redact_bearer(m):
        nonlocal count
        prefix = m.group(1)
        token = m.group(2)
        if token != "[REDACTED]":
            count += 1
        return f"{prefix}[REDACTED]"

    text = re.sub(r'((?:Authorization|Proxy-Authorization|X-Auth-Token|X-Access-Token|X-CSRF-Token|X-Session-Token)(?::\s*|\s+)(?:Bearer|Token)?\s*)([^\s\r\n]+)', _redact_bearer, text, flags=re.I)

    # 3. Cookie & Set-Cookie headers
    def _redact_cookie_header(m):
        nonlocal count
        header_name = m.group(1)
        header_val = m.group(2)
        if header_val.strip() != "[REDACTED]":
            count += 1
        return f"{header_name}[REDACTED]"

    text = re.sub(r'((?:Set-Cookie|Cookie):\s*)([^\r\n]+)', _redact_cookie_header, text, flags=re.I)

    # 4. X-API-Key header
    def _redact_apikey_header(m):
        nonlocal count
        header_name = m.group(1)
        header_val = m.group(2)
        if header_val.strip() != "[REDACTED]":
            count += 1
        return f"{header_name}[REDACTED]"

    text = re.sub(r'((?:X-API-Key|X-ApiKey|X-Secret):\s*)([^\r\n]+)', _redact_apikey_header, text, flags=re.I)

    # 5. Sensitive query/form parameters in URLs or strings: ?password=xxx, &token=yyy, or PASSWORD=zzz
    def _redact_query_param(m):
        nonlocal count
        param_prefix = m.group(1)
        param_val = m.group(2)
        if param_val != "[REDACTED]":
            count += 1
        return f"{param_prefix}[REDACTED]"

    param_pattern = r'((?:^|[\s?&])(?:password|passwd|pass|secret|token|access_token|refresh_token|id_token|api_key|apikey|auth|authorization|session|session_id|sessionid|cookie|csrf|xsrf|private_key|client_secret)=)([^&\s\r\n"\']+)'
    text = re.sub(param_pattern, _redact_query_param, text, flags=re.I)

    # 6. JSON-style key-value pairs in text (for HTTP bodies, embedded JSON, or fallback): "password": "secret"
    def _redact_json_str(m):
        nonlocal count
        prefix = m.group(1)
        val = m.group(2)
        if val != "[REDACTED]":
            count += 1
        return f'{prefix}"[REDACTED]"'

    text = re.sub(r'("(?:password|passwd|pass|secret|token|access_token|refresh_token|id_token|api_key|apikey|auth|authorization|session|session_id|sessionid|cookie|csrf|xsrf|private_key|client_secret)"\s*:\s*")([^"]+)"', _redact_json_str, text, flags=re.I)

    def _redact_json_raw(m):
        nonlocal count
        prefix = m.group(1)
        val = m.group(2)
        if val != "[REDACTED]" and val != '"[REDACTED]"':
            count += 1
        return f'{prefix}"[REDACTED]"'

    text = re.sub(r'("(?:password|passwd|pass|secret|token|access_token|refresh_token|id_token|api_key|apikey|auth|authorization|session|session_id|sessionid|cookie|csrf|xsrf|private_key|client_secret)"\s*:\s*)([^\s,\}\r\n]+)', _redact_json_raw, text, flags=re.I)

    return text, count


def sanitize_json_data(data: any) -> tuple[any, int]:
    """Recursively sanitize JSON data structures, redacting sensitive keys."""
    count = 0
    if isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            is_sensitive = (k_lower in SENSITIVE_PARAM_NAMES or
                            any(s in k_lower for s in ("password", "passwd", "secret", "access_token", "refresh_token", "id_token", "api_key", "client_secret", "private_key")))
            if is_sensitive:
                if v != "[REDACTED]":
                    count += 1
                new_dict[k] = "[REDACTED]"
            else:
                new_v, sub_count = sanitize_json_data(v)
                count += sub_count
                new_dict[k] = new_v
        return new_dict, count
    elif isinstance(data, list):
        new_list = []
        for item in data:
            new_item, sub_count = sanitize_json_data(item)
            count += sub_count
            new_list.append(new_item)
        return new_list, count
    elif isinstance(data, str):
        sanitized_str, str_count = _sanitize_text_content(data)
        return sanitized_str, str_count
    return data, 0


def sanitize_form_data(body_str: str) -> tuple[str, int]:
    """Sanitize form-urlencoded data string."""
    parts = body_str.split("&")
    new_parts = []
    count = 0
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            k_un = urllib.parse.unquote(k)
            k_lower = k_un.lower()
            is_sensitive = (k_lower in SENSITIVE_PARAM_NAMES or
                            any(s in k_lower for s in ("password", "passwd", "secret", "access_token", "refresh_token", "id_token", "api_key", "client_secret", "private_key")))
            if is_sensitive:
                if v != "[REDACTED]":
                    count += 1
                new_parts.append(f"{k}=[REDACTED]")
            else:
                v_san, c_san = _sanitize_text_content(v)
                count += c_san
                new_parts.append(f"{k}={v_san}")
        else:
            new_parts.append(part)
    return "&".join(new_parts), count


def sanitize_canonical_evidence(content: str | bytes, ev_type: str = "note") -> SanitizationResult:
    """Canonical Evidence Sanitization Engine for all evidence types."""
    if ev_type in ("screenshot", "attachment") and isinstance(content, bytes):
        return SanitizationResult(
            content=content,
            status="not_inspected",
            redactions_count=0
        )

    if not isinstance(content, str):
        if isinstance(content, bytes):
            try:
                content = content.decode("utf-8")
            except Exception:
                return SanitizationResult(
                    content=content,
                    status="not_inspected",
                    redactions_count=0
                )
        else:
            return SanitizationResult(
                content=str(content),
                status="not_required",
                redactions_count=0
            )

    try:
        total_redactions = 0
        working_content = content

        # Check if content is JSON
        trimmed = working_content.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                parsed_json = json.loads(trimmed)
                sanitized_json, json_redactions = sanitize_json_data(parsed_json)
                working_content = json.dumps(sanitized_json, indent=2)
                total_redactions += json_redactions
            except Exception:
                pass

        # Check if content is form-urlencoded
        if "password=" in working_content.lower() or "token=" in working_content.lower() or "secret=" in working_content.lower():
            if not working_content.startswith("GET ") and not working_content.startswith("POST "):
                if "=" in working_content and ("&" in working_content or working_content.count("=") == 1):
                    try:
                        working_content, form_redactions = sanitize_form_data(working_content)
                        total_redactions += form_redactions
                    except Exception:
                        pass

        # Apply canonical regex text sanitization across headers/URLs/strings
        final_content, text_redactions = _sanitize_text_content(working_content)
        total_redactions += text_redactions

        return SanitizationResult(
            content=final_content,
            status="sanitized",
            redactions_count=total_redactions
        )
    except Exception:
        # FAIL-SAFE: If sanitization throws an error, return status='failed'
        return SanitizationResult(
            content="",
            status="failed",
            redactions_count=0
        )


def _sanitize_sensitive(val: str) -> str:
    """Wrapper using the canonical sanitization engine."""
    if not isinstance(val, str):
        return val
    res = sanitize_canonical_evidence(val)
    return res.content if res.status != "failed" else val


def sanitize_evidence(content: str | bytes, ev_type: str = "note") -> tuple[str | bytes, bool, str, int]:
    """Canonical sanitization hook for security evidence before storage."""
    res = sanitize_canonical_evidence(content, ev_type=ev_type)
    return res.content, res.redacted, res.status, res.redactions_count


def check_authorization(target_domain: str | None = None) -> tuple[bool, str]:
    """Check .engagement/authorization.yaml and scope boundaries."""
    d = _get_eng_dir()
    auth_file = d / "authorization.yaml"
    if not auth_file.exists():
        return False, "Missing authorization.yaml in .engagement/ directory."

    try:
        content = auth_file.read_text(encoding="utf-8")
        if "authorized: true" not in content.lower():
            return False, "Authorization revoked or set to false in authorization.yaml."
    except Exception as e:
        return False, f"Could not read authorization.yaml: {e}"

    return True, "Authorized"


def get_engagement_scope() -> list[str]:
    d = _get_eng_dir()
    t_file = d / "target.yaml"
    scopes = []
    if t_file.exists():
        try:
            for line in t_file.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("-") or "scope" in line:
                    val = line.split(":")[-1].replace("-", "").strip().strip('"').strip("'")
                    if val and val != "scope":
                        scopes.append(val.lower())
        except Exception:
            pass
    return scopes


def is_hostname_in_scope(hostname: str, scope_list: list[str]) -> bool:
    if not scope_list:
        return True
    host = hostname.lower().strip()
    for sc in scope_list:
        sc_clean = sc.lower().strip()
        if sc_clean.startswith("*."):
            domain_part = sc_clean[2:]
            if host == domain_part or host.endswith("." + domain_part):
                return True
        elif host == sc_clean:
            return True
    return False

STATE_COMMAND_PERMISSIONS = {
    "DISCOVERY": {
        "allowed": ["doctor", "engagement", "recon", "surface", "memory", "technology", "state", "evidence", "finding", "findings", "mission", "run-mission", "knowledge", "analyze", "skills", "validate", "exec", "ai", "web", "agent", "agents", "tasks", "fleet", "workers", "browser", "runtime", "auth", "monitor", "assets", "changes", "alerts", "research"],
        "disallowed_subcommands": {}
    },
    "ANALYSIS": {
        "allowed": ["doctor", "engagement", "surface", "classify", "memory", "technology", "state", "evidence", "finding", "findings", "mission", "run-mission", "knowledge", "analyze", "skills", "validate", "exec", "ai", "web", "agent", "agents", "tasks", "fleet", "workers", "browser", "runtime", "auth", "monitor", "assets", "changes", "alerts", "research"],
        "disallowed_subcommands": {}
    },
    "VALIDATION": {
        "allowed": ["doctor", "engagement", "memory", "technology", "duplicate-check", "triage", "state", "evidence", "finding", "findings", "mission", "run-mission", "knowledge", "analyze", "skills", "validate", "exec", "ai", "web", "agent", "agents", "tasks", "fleet", "workers", "browser", "runtime", "auth", "monitor", "assets", "changes", "alerts", "research"],
        "disallowed_subcommands": {}
    },
    "REPORTING": {
        "allowed": ["doctor", "engagement", "memory", "technology", "findings", "report", "state", "evidence", "finding", "mission", "run-mission", "knowledge", "analyze", "skills", "validate", "exec", "ai", "web", "agent", "agents", "tasks", "fleet", "workers", "browser", "runtime", "auth", "monitor", "assets", "changes", "alerts", "research"],
        "disallowed_subcommands": {}
    }
}
def check_state_permission(cmd_name: str, args: argparse.Namespace) -> tuple[bool, str]:
    """Strictly enforce command execution based on current workflow state."""
    d = _get_eng_dir()
    if not d.exists():
        return True, ""  # No engagement active yet

    state_file = d / "state.json"
    if not state_file.exists():
        return True, ""

    try:
        state_data = json.loads(state_file.read_text(encoding="utf-8"))
        curr_state = state_data.get("state", "DISCOVERY")
    except Exception:
        return True, ""

    perm = STATE_COMMAND_PERMISSIONS.get(curr_state, {})
    allowed_cmds = perm.get("allowed", [])

    if cmd_name not in allowed_cmds:
        # Determine required state for this command
        req_state = "UNKNOWN"
        for st, pinfo in STATE_COMMAND_PERMISSIONS.items():
            if cmd_name in pinfo.get("allowed", []):
                req_state = st
                break

        msg = (f"ERROR:\n"
               f"Command 'nyx {cmd_name}' is not available during {curr_state}.\n\n"
               f"Current state:  {curr_state}\n"
               f"Required state: {req_state}\n\n"
               f"Transition using:\n"
               f"  nyx state {req_state}")
        return False, msg

    return True, ""


def sync_recon_to_engagement(target: str, subs: set, resolved: dict, live: list) -> tuple[int, int, int]:
    """Synchronize recon discovered endpoints directly into .engagement/endpoints.json."""
    d = _get_eng_dir()
    if not d.exists():
        say(color("  Notice: No active engagement workspace found (.engagement/).", "yellow"))
        say("  To persist recon endpoints into engagement memory, initialize an engagement first:")
        say(f"    nyx engagement init {target}\n")
        return 0, 0, 0

    ep_file = d / "endpoints.json"
    try:
        endpoints = json.loads(ep_file.read_text(encoding="utf-8")) if ep_file.exists() else []
    except Exception:
        endpoints = []

    existing_by_url = {e.get("url", "").strip().lower(): e for e in endpoints if e.get("url")}
    total_disc = len(live) + len(resolved)
    new_cnt = 0
    known_cnt = 0

    # Process live HTTP hosts
    for rec in live:
        url = normalize_url(rec.get("url") or "")
        if not url:
            continue
        key = url.lower()
        if key in existing_by_url:
            known_cnt += 1
            existing_obj = existing_by_url[key]
            sources = existing_obj.setdefault("sources", ["recon" if existing_obj.get("source") == "recon" else "manual"])
            if "recon" not in sources:
                sources.append("recon")
            existing_obj["status"] = rec.get("code") or existing_obj.get("status")
            existing_obj["server"] = rec.get("server") or existing_obj.get("server")
            existing_obj["title"] = rec.get("title") or existing_obj.get("title")
        else:
            new_cnt += 1
            new_obj = {
                "url": url,
                "method": "GET",
                "source": "recon",
                "sources": ["recon"],
                "discovered_at": datetime.datetime.now().isoformat(),
                "status": rec.get("code", 200),
                "server": rec.get("server", ""),
                "title": rec.get("title", ""),
                "priority": _rank_host(rec.get("host", ""))[0]
            }
            endpoints.append(new_obj)
            existing_by_url[key] = new_obj

    # Process DNS-only hosts
    for host in sorted(resolved):
        if any(rec.get("host") == host for rec in live):
            continue
        url = normalize_url(f"https://{host}/")
        key = url.lower()
        if key in existing_by_url:
            known_cnt += 1
        else:
            new_cnt += 1
            new_obj = {
                "url": url,
                "method": "GET",
                "source": "recon",
                "sources": ["recon"],
                "discovered_at": datetime.datetime.now().isoformat(),
                "status": "DNS-only",
                "ips": resolved[host],
                "priority": _rank_host(host)[0]
            }
            endpoints.append(new_obj)
            existing_by_url[key] = new_obj

    ep_file.write_text(json.dumps(endpoints, indent=2), encoding="utf-8")
    return total_disc, new_cnt, known_cnt


def get_engagement_scope() -> list[str]:
    """Load target domains and wildcard patterns from target.yaml and authorization.yaml."""
    d = _get_eng_dir()
    scopes = []

    for fname in ["target.yaml", "authorization.yaml"]:
        f_path = d / fname
        if f_path.exists():
            try:
                content = f_path.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line_str = line.strip()
                    if line_str.startswith("-"):
                        clean = line_str.lstrip("-").strip().strip('"').strip("'")
                        if clean and clean.lower() not in ("web", "api", "third-party", "production-user-data"):
                            scopes.append(clean.lower())
                    elif "domain:" in line_str or "name:" in line_str:
                        clean = re.sub(r'^(?:domain:\s*|name:\s*)', '', line_str).strip().strip('"').strip("'")
                        if clean and not clean.startswith("target:") and not clean.startswith("scope:") and not clean.startswith("exclusions:"):
                            scopes.append(clean.lower())
            except Exception:
                pass

    return list(dict.fromkeys(scopes))


def is_host_in_scope(host: str, scopes: list[str]) -> bool:
    """Check if host is strictly inside declared engagement scope."""
    if not host or not scopes:
        return False

    # Normalize host: strip whitespace, trailing dot, lower case, remove port
    h = host.strip().lower()
    if h.endswith("."):
        h = h[:-1]
    if ":" in h:
        h = h.split(":")[0]

    for rule in scopes:
        r = rule.strip().lower()
        if r.endswith("."):
            r = r[:-1]
        if ":" in r:
            r = r.split(":")[0]
        if not r:
            continue

        if r.startswith("*."):
            base = r[2:]
            if h == base or h.endswith("." + base):
                return True
        else:
            if h == r or h.endswith("." + r):
                return True

    return False


def import_burp_xml(xml_path: Path, include_out_of_scope: bool = False) -> dict:
    """Parse Burp Suite HTTP History XML with scope enforcement and merge endpoints cleanly into .engagement/endpoints.json."""
    if not xml_path.exists():
        raise FileNotFoundError(f"Burp XML file not found: {xml_path}")

    # Enforce authorization boundary
    auth_ok, auth_msg = check_authorization()
    if not auth_ok:
        raise RuntimeError(f"Authorization requirement failed: {auth_msg}")

    import xml.etree.ElementTree as ET
    import base64

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise ValueError(f"Malformed Burp XML history file: {e}")

    items = root.findall(".//item")
    parsed_cnt = len(items)
    valid_cnt = 0
    in_scope_cnt = 0
    out_of_scope_cnt = 0
    new_cnt = 0
    existing_cnt = 0
    redacted_cnt = 0

    d = _get_eng_dir()
    if not d.exists():
        raise RuntimeError("No active engagement workspace found (.engagement/). Run 'nyx engagement init <target>' first.")

    scopes = get_engagement_scope()

    ep_file = d / "endpoints.json"
    endpoints = json.loads(ep_file.read_text(encoding="utf-8")) if ep_file.exists() else []

    # Endpoint deduplication key: scheme + host + port + path + method
    def _ep_key(scheme, host, port, path, method):
        return f"{scheme.lower()}://{host.lower()}:{port}{path.lower()}|{method.upper()}"

    existing_map = {}
    for e in endpoints:
        u = e.get("url", "")
        m = e.get("method", "GET")
        if u:
            purl = urllib.parse.urlparse(u)
            port = purl.port or (443 if purl.scheme == "https" else 80)
            k = _ep_key(purl.scheme or "http", purl.netloc.split(":")[0], port, purl.path or "/", m)
            existing_map[k] = e

    for item in items:
        try:
            url_node = item.find("url")
            host_node = item.find("host")
            port_node = item.find("port")
            proto_node = item.find("protocol")
            method_node = item.find("method")
            path_node = item.find("path")
            status_node = item.find("status")

            if url_node is None or host_node is None or method_node is None:
                continue

            raw_url = url_node.text or ""
            host = host_node.text or ""
            port = int(port_node.text) if port_node is not None and port_node.text else (443 if (proto_node is not None and proto_node.text == "https") else 80)
            proto = proto_node.text if proto_node is not None and proto_node.text else "http"
            method = (method_node.text or "GET").upper()
            path = path_node.text or "/"
            status_code = int(status_node.text) if status_node is not None and status_node.text else None

            if not raw_url or not host:
                continue

            valid_cnt += 1

            # Scope matching gate
            in_scope = is_host_in_scope(host, scopes)
            if in_scope:
                in_scope_cnt += 1
            else:
                out_of_scope_cnt += 1
                if not include_out_of_scope:
                    continue  # Reject out-of-scope endpoints by default

            # Extract query parameters & redact sensitive param values
            parsed_url = urllib.parse.urlparse(raw_url)
            queryParams = urllib.parse.parse_qs(parsed_url.query)
            params_list = []
            SENSITIVE_PARAM_NAMES = {"password", "pass", "secret", "token", "api_key", "apikey", "access_token", "auth", "authorization", "session", "sessionid", "cookie", "jwt", "bearer", "key"}
            for qk, qvals in queryParams.items():
                sanitized_k = _sanitize_sensitive(qk)
                is_sensitive_param = qk.lower() in SENSITIVE_PARAM_NAMES or any(s in qk.lower() for s in ("token", "secret", "pass", "auth", "key"))
                for qv in qvals:
                    if is_sensitive_param:
                        sanitized_v = "[REDACTED]"
                        redacted_cnt += 1
                    else:
                        sanitized_v = _sanitize_sensitive(qv)
                        if sanitized_v != qv:
                            redacted_cnt += 1
                    params_list.append({"name": sanitized_k, "value": sanitized_v})

            # Extract & sanitize request headers
            req_node = item.find("request")
            req_text = ""
            if req_node is not None and req_node.text:
                if req_node.attrib.get("base64") == "true":
                    try:
                        req_text = base64.b64decode(req_node.text).decode("utf-8", errors="replace")
                    except Exception:
                        req_text = ""
                else:
                    req_text = req_node.text

            if req_text:
                sanitized_req = _sanitize_sensitive(req_text)
                if sanitized_req != req_text:
                    redacted_cnt += 1

            # Check deduplication
            key = _ep_key(proto, host, port, parsed_url.path or "/", method)
            if key in existing_map:
                existing_cnt += 1
                rec = existing_map[key]
                sources = rec.setdefault("sources", [rec.get("source", "recon")])
                if "burp" not in sources:
                    sources.append("burp")
                rec["response_status"] = status_code or rec.get("response_status")
                rec["parameters"] = params_list or rec.get("parameters", [])
            else:
                new_cnt += 1
                clean_url = normalize_url(f"{proto}://{host}{':' + str(port) if (proto=='http' and port!=80) or (proto=='https' and port!=443) else ''}{parsed_url.path or '/'}")
                new_rec = {
                    "url": clean_url,
                    "full_url": _sanitize_sensitive(raw_url),
                    "method": method,
                    "source": "burp",
                    "sources": ["burp"],
                    "status": "observed",
                    "response_status": status_code,
                    "parameters": params_list,
                    "imported_at": datetime.datetime.now().isoformat()
                }
                endpoints.append(new_rec)
                existing_map[key] = new_rec

        except Exception:
            continue

    # Atomic write to avoid partial corruption
    temp_ep_file = ep_file.with_suffix(".tmp")
    temp_ep_file.write_text(json.dumps(endpoints, indent=2), encoding="utf-8")
    temp_ep_file.replace(ep_file)

    return {
        "parsed": parsed_cnt,
        "valid": valid_cnt,
        "in_scope": in_scope_cnt,
        "out_of_scope": out_of_scope_cnt,
        "new": new_cnt,
        "existing": existing_cnt,
        "redacted": redacted_cnt
    }


def cmd_memory(args: argparse.Namespace) -> int:
    svc = EngagementService()
    subcmd = args.mem_subcommand
    if subcmd == "import-burp":
        xml_file = Path(args.file)
        inc_oos = getattr(args, "include_out_of_scope", False)
        section("Burp Suite History Import")
        if inc_oos:
            say(color("  [WARNING] Administrative override active: Including out-of-scope traffic in import!", "yellow"))
        try:
            stats = svc.import_burp_xml(xml_file, include_out_of_scope=inc_oos)
            say("  Burp import completed.\n")
            say(f"  Requests parsed:           {color(str(stats['parsed']), 'bold')}")
            say(f"  In-scope:                  {color(str(stats['in_scope']), 'green')}")
            say(f"  Out-of-scope:              {color(str(stats['out_of_scope']), 'yellow' if stats['out_of_scope']>0 else 'dim')}")
            say(f"  New endpoints:             {color(str(stats['new']), 'green')}")
            say(f"  Existing endpoints:        {color(str(stats['existing']), 'cyan')}")
            say(f"  Sensitive values redacted: {color(str(stats['redacted']), 'yellow')}")
            return 0
        except Exception as e:
            say(color(f"  [error] Burp import failed: {e}", "red"))
            return 1

    if subcmd == "add":
        mtype = args.type
        val = args.value
        prio = getattr(args, "priority", "P2")
        cat = getattr(args, "category", "frameworks")
        res = svc.add_memory(type_=mtype, value=val, priority=prio, category=cat)
        if res.get("status") == "error":
            say(color(f"  [error] {res.get('message')}", "red"))
            return 1
        if mtype == "endpoint":
            say(color(f"  Added endpoint: {res.get('value')}", "green"))
        elif mtype == "technology":
            say(color(f"  Added technology [{cat}]: {res.get('value')}", "green"))
        elif mtype == "vector":
            say(color(f"  Added tested vector: {res.get('value')}", "green"))
        else:
            say(color(f"  Added note entry ({mtype}): {res.get('value')}", "green"))
        return 0

    elif subcmd == "search":
        res = svc.search_memory(query=args.query)
        if res.get("status") == "error":
            say(color(f"  [error] {res.get('message')}", "red"))
            return 1
        section(f"Memory Search Results for: {args.query}")
        results_list = res.get("results", [])
        total_matches = sum(len(r.get("matches", [])) for r in results_list)
        if not results_list or total_matches == 0:
            say("  No matching records found in engagement memory.")
        else:
            for item in results_list:
                say(color(f"  Found matches in {item['file']}:", "bold"))
                for match_line in item["matches"]:
                    say(f"    {match_line}")
        return 0

    elif subcmd == "list":
        section("Engagement Memory Inventory")
        mtype = getattr(args, "type", "all")
        eng_dir = Path(".engagement")
        if not eng_dir.exists():
            say(color("  [error] No active engagement workspace found in .engagement/", "red"))
            return 1

        if mtype in ("all", "endpoint"):
            ep_file = eng_dir / "endpoints.json"
            eps = json.loads(ep_file.read_text(encoding="utf-8")) if ep_file.exists() else []
            say(color(f"  Endpoints ({len(eps)}):", "bold"))
            for ep in eps[:20]:
                say(f"    • [{ep.get('priority', 'P2')}] {ep.get('url')} (Status: {ep.get('status', 'N/A')})")
            if len(eps) > 20:
                say(f"    ... and {len(eps) - 20} more")

        if mtype in ("all", "technology"):
            tech_file = eng_dir / "technologies.json"
            techs = json.loads(tech_file.read_text(encoding="utf-8")) if tech_file.exists() else {}
            flat_techs = [f"{cat}:{item}" for cat, items in techs.items() if isinstance(items, list) for item in items]
            say(color(f"  Technologies ({len(flat_techs)}):", "bold"))
            for t in flat_techs:
                say(f"    • {t}")

        if mtype in ("all", "vector"):
            vec_file = eng_dir / "tested_vectors.json"
            vecs = json.loads(vec_file.read_text(encoding="utf-8")) if vec_file.exists() else []
            say(color(f"  Tested Vectors ({len(vecs)}):", "bold"))
            for v in vecs[:15]:
                say(f"    • {v.get('vector')} on {v.get('endpoint')} -> {v.get('result')}")
            if len(vecs) > 15:
                say(f"    ... and {len(vecs) - 15} more")

        if mtype in ("all", "note"):
            notes_file = eng_dir / "notes.md"
            if notes_file.exists():
                lines = [l for l in notes_file.read_text(encoding="utf-8").splitlines() if l.strip()]
                say(color(f"  Notes ({len(lines)} entries):", "bold"))
                for line in lines[:10]:
                    say(f"    {line}")
        return 0

    return 0


def cmd_state(args: argparse.Namespace) -> int:
    svc = EngagementService()
    req_mode = getattr(args, "mode", None)
    ns = getattr(args, "new_state", None)
    force = getattr(args, "force_state", False) or getattr(args, "force", False)

    res = svc.set_state(new_state=ns, mode=req_mode, force=force)
    if res.get("status") == "error":
        say(color(f"  [error] {res.get('message')}", "red"))
        if res.get("code") == "INVALID_TRANSITION":
            say(f"  Mode '{res.get('curr_mode')}' rule violation.")
            say(f"  To override this check administratively, pass:  nyx state {res.get('requested_state')} --force-state")
            say(f"  Or switch workflow mode to RESEARCH:          nyx state --mode research")
        return 1

    if req_mode and res.get("curr_mode"):
        say(color(f"  Workflow mode set to: {res.get('curr_mode')}", "green"))

    if ns:
        if res.get("force_applied"):
            say(color(f"  [warning] Administrative state override applied: {res.get('old_state')} -> {res.get('new_state')}", "yellow"))
        say(color(f"  State updated: {res.get('old_state')} -> {res.get('new_state')} (Mode: {res.get('mode')})", "green"))
    elif not req_mode:
        section("Current Bug Hunting Workflow State")
        say(f"  Active State:  {color(res.get('curr_state'), 'cyan')}")
        say(f"  Workflow Mode: {color(res.get('curr_mode'), 'yellow')}")
        say(f"  Completed:     {', '.join(res.get('completed', []))}")
        say(f"  Last Updated:  {res.get('updated_at', 'N/A')}")
    return 0





VALID_FINDING_STATES = ["HYPOTHESIS", "INVESTIGATING", "VALIDATED", "CONFIRMED", "REPORTED", "REJECTED"]

ALLOWED_FINDING_TRANSITIONS = {
    "HYPOTHESIS": ["INVESTIGATING", "REJECTED"],
    "INVESTIGATING": ["VALIDATED", "REJECTED"],
    "VALIDATED": ["CONFIRMED", "REJECTED"],
    "CONFIRMED": ["REPORTED", "REJECTED"],
    "REPORTED": [],
    "REJECTED": []
}


def _generate_finding_id(eng_dir: Path, year: int | None = None) -> str:
    """Generate unique finding ID (FH-YYYY-XXX)."""
    if year is None:
        year = datetime.datetime.now().year
    findings_root = eng_dir / "findings"
    max_seq = 0
    if findings_root.exists():
        for f_dir in findings_root.iterdir():
            if f_dir.is_dir() and f_dir.name.startswith(f"FH-{year}-"):
                seq_str = f_dir.name.split("-")[-1]
                if seq_str.isdigit():
                    max_seq = max(max_seq, int(seq_str))

    f_file = eng_dir / "findings.json"
    if f_file.exists():
        try:
            items = json.loads(f_file.read_text(encoding="utf-8"))
            for item in items:
                fid = item.get("finding_id", "")
                if fid.startswith(f"FH-{year}-"):
                    seq_str = fid.split("-")[-1]
                    if seq_str.isdigit():
                        max_seq = max(max_seq, int(seq_str))
        except Exception:
            pass

    return f"FH-{year}-{max_seq + 1:03d}"


def _sync_findings_index(eng_dir: Path):
    """Sync lightweight index .engagement/findings.json from .engagement/findings/*/finding.json."""
    findings_root = eng_dir / "findings"
    index_items = []
    if findings_root.exists():
        for f_dir in sorted(findings_root.iterdir()):
            if f_dir.is_dir():
                f_json = f_dir / "finding.json"
                if f_json.exists():
                    try:
                        data = json.loads(f_json.read_text(encoding="utf-8"))
                        index_items.append({
                            "finding_id": data.get("finding_id"),
                            "title": data.get("title"),
                            "status": data.get("status"),
                            "severity": data.get("severity"),
                            "endpoint": data.get("endpoint"),
                            "parameter": data.get("parameter"),
                            "vulnerability": data.get("vulnerability"),
                            "created_at": data.get("created_at"),
                            "updated_at": data.get("updated_at"),
                            "evidence_ids": data.get("evidence_ids", []),
                            "tags": data.get("tags", [])
                        })
                    except Exception:
                        pass

    index_file = eng_dir / "findings.json"
    temp_index = index_file.with_suffix(".json.tmp")
    temp_index.write_text(json.dumps(index_items, indent=2), encoding="utf-8")
    temp_index.replace(index_file)


def _get_finding_dir(eng_dir: Path, finding_id: str, create: bool = False) -> tuple[Path | None, str]:
    """Get path to .engagement/findings/<finding_id>/."""
    f_dir = eng_dir / "findings" / finding_id
    if not f_dir.exists() and not create:
        return None, f"Finding '{finding_id}' does not exist in engagement workspace."

    if create:
        f_dir.mkdir(parents=True, exist_ok=True)

    return f_dir, "OK"


def cmd_finding(args: argparse.Namespace) -> int:
    """CLI dispatcher for 'nyx finding' lifecycle commands."""
    d = _get_eng_dir()
    if not d.exists():
        say(color("  [error] No active engagement workspace found. Run nyx engagement init <target> first.", "red"))
        return 1

    subcmd = args.finding_subcommand

    if subcmd == "create":
        title = _sanitize_sensitive(args.title or "Untitled Finding")
        ep = _sanitize_sensitive(args.endpoint or "") if args.endpoint else None
        param = _sanitize_sensitive(args.parameter or "") if args.parameter else None
        vuln = _sanitize_sensitive(args.vulnerability or "") if args.vulnerability else None
        sev = getattr(args, "severity", None)
        tags = [_sanitize_sensitive(t) for t in (args.tag or [])]

        fid = _generate_finding_id(d)
        f_dir, _ = _get_finding_dir(d, fid, create=True)

        now_str = datetime.datetime.now().isoformat()
        finding_data = {
            "finding_id": fid,
            "title": title,
            "status": "HYPOTHESIS",
            "severity": sev,
            "vrt": None,
            "cwe": None,
            "endpoint": ep,
            "parameter": param,
            "vulnerability": vuln,
            "created_at": now_str,
            "updated_at": now_str,
            "evidence_ids": [],
            "tags": tags
        }

        (f_dir / "finding.json").write_text(json.dumps(finding_data, indent=2), encoding="utf-8")

        timeline = [{
            "timestamp": now_str,
            "event": "created",
            "from": None,
            "to": "HYPOTHESIS",
            "reason": _sanitize_sensitive(getattr(args, "description", None) or "Finding created"),
            "source": "nyx"
        }]
        (f_dir / "timeline.json").write_text(json.dumps(timeline, indent=2), encoding="utf-8")
        (f_dir / "hypotheses.json").write_text("[]", encoding="utf-8")

        notes_content = f"# Research Notes — {fid}\n\n- [{now_str[:16]}] Finding created in HYPOTHESIS state.\n"
        if getattr(args, "description", None):
            notes_content += f"- Description: {_sanitize_sensitive(args.description)}\n"
        (f_dir / "notes.md").write_text(notes_content, encoding="utf-8")

        _sync_findings_index(d)

        section("Finding Created")
        say(f"  Finding ID: {color(fid, 'bold')}")
        say(f"  Title:      {color(title, 'cyan')}")
        say(f"  Status:     {color('HYPOTHESIS', 'yellow')}")
        if ep:
            say(f"  Endpoint:   {ep}")
        return 0

    elif subcmd == "list":
        _sync_findings_index(d)
        index_file = d / "findings.json"
        findings = []
        if index_file.exists():
            try:
                findings = json.loads(index_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        section("Engagement Findings")
        if not findings:
            say("  No findings recorded in engagement workspace.")
            return 0

        for f in findings:
            fid = f.get("finding_id")
            title = f.get("title")
            st = f.get("status")
            ep = f.get("endpoint") or "N/A"
            say(f"Finding ID: {color(fid, 'bold')}")
            say(f"Title:      {color(title, 'cyan')}")
            say(f"State:      {color(st, 'yellow' if st in ('HYPOTHESIS', 'INVESTIGATING') else ('green' if st in ('VALIDATED', 'CONFIRMED', 'REPORTED') else 'red'))}")
            say(f"Endpoint:   {ep}\n")
        return 0

    elif subcmd == "show":
        fid = args.finding_id
        f_dir = d / "findings" / fid
        f_json = f_dir / "finding.json"
        if not f_json.exists():
            say(color(f"  [error] Finding '{fid}' not found in engagement workspace.", "red"))
            return 1

        fdata = json.loads(f_json.read_text(encoding="utf-8"))
        timeline_p = f_dir / "timeline.json"
        tdata = json.loads(timeline_p.read_text(encoding="utf-8")) if timeline_p.exists() else []

        hyp_p = f_dir / "hypotheses.json"
        hdata = json.loads(hyp_p.read_text(encoding="utf-8")) if hyp_p.exists() else []

        section(f"Finding Details: {fid}")
        say(f"  Finding ID:       {color(fdata.get('finding_id'), 'bold')}")
        say(f"  Title:            {color(fdata.get('title'), 'cyan')}")
        say(f"  Status:           {color(fdata.get('status'), 'yellow')}")
        say(f"  Endpoint:         {fdata.get('endpoint') or 'N/A'}")
        say(f"  Parameter:        {fdata.get('parameter') or 'N/A'}")
        say(f"  Severity:         {fdata.get('severity') or 'N/A'}")
        say(f"  Created At:       {fdata.get('created_at')}")
        say(f"  Updated At:       {fdata.get('updated_at')}")
        say(f"  Evidence Count:   {len(fdata.get('evidence_ids', []))}")
        say(f"  Evidence IDs:     {', '.join(fdata.get('evidence_ids', [])) if fdata.get('evidence_ids') else 'None'}")
        say(f"  Hypotheses Count: {len(hdata)}")
        say(f"  Timeline Events:  {len(tdata)}")
        say(f"  Tags:             {', '.join(fdata.get('tags', [])) if fdata.get('tags') else 'None'}\n")
        return 0

    elif subcmd == "transition":
        fid = args.finding_id
        new_state = args.new_state
        reason = _sanitize_sensitive(args.reason)

        f_dir = d / "findings" / fid
        f_json = f_dir / "finding.json"
        if not f_json.exists():
            say(color(f"  [error] Finding '{fid}' not found in engagement workspace.", "red"))
            return 1

        fdata = json.loads(f_json.read_text(encoding="utf-8"))
        curr_state = fdata.get("status", "HYPOTHESIS")

        allowed = ALLOWED_FINDING_TRANSITIONS.get(curr_state, [])

        if new_state not in allowed:
            say(color(f"ERROR:\nInvalid finding transition.\n\nCurrent:\n{curr_state}\n\nRequested:\n{new_state}\n\nAllowed:\n{', '.join(allowed) if allowed else 'None'}", "red"))
            return 1

        now_str = datetime.datetime.now().isoformat()
        fdata["status"] = new_state
        fdata["updated_at"] = now_str
        f_json.write_text(json.dumps(fdata, indent=2), encoding="utf-8")

        timeline_p = f_dir / "timeline.json"
        tdata = json.loads(timeline_p.read_text(encoding="utf-8")) if timeline_p.exists() else []
        tdata.append({
            "timestamp": now_str,
            "event": "transition",
            "from": curr_state,
            "to": new_state,
            "reason": reason,
            "source": "nyx"
        })
        timeline_p.write_text(json.dumps(tdata, indent=2), encoding="utf-8")

        _sync_findings_index(d)

        section("Finding Transitioned")
        say(f"  Finding ID: {color(fid, 'bold')}")
        say(f"  State:      {color(curr_state, 'yellow')} -> {color(new_state, 'green')}")
        say(f"  Reason:     {reason}")
        return 0

    elif subcmd == "reject":
        fid = args.finding_id
        reason = _sanitize_sensitive(args.reason)

        f_dir = d / "findings" / fid
        f_json = f_dir / "finding.json"
        if not f_json.exists():
            say(color(f"  [error] Finding '{fid}' not found in engagement workspace.", "red"))
            return 1

        fdata = json.loads(f_json.read_text(encoding="utf-8"))
        curr_state = fdata.get("status", "HYPOTHESIS")

        allowed = ALLOWED_FINDING_TRANSITIONS.get(curr_state, [])
        if "REJECTED" not in allowed:
            say(color(f"ERROR:\nInvalid finding transition.\n\nCurrent:\n{curr_state}\n\nRequested:\nREJECTED\n\nAllowed:\n{', '.join(allowed) if allowed else 'None'}", "red"))
            return 1

        now_str = datetime.datetime.now().isoformat()
        fdata["status"] = "REJECTED"
        fdata["updated_at"] = now_str
        f_json.write_text(json.dumps(fdata, indent=2), encoding="utf-8")

        timeline_p = f_dir / "timeline.json"
        tdata = json.loads(timeline_p.read_text(encoding="utf-8")) if timeline_p.exists() else []
        tdata.append({
            "timestamp": now_str,
            "event": "rejected",
            "from": curr_state,
            "to": "REJECTED",
            "reason": reason,
            "source": "nyx"
        })
        timeline_p.write_text(json.dumps(tdata, indent=2), encoding="utf-8")

        _sync_findings_index(d)

        section("Finding Rejected")
        say(f"  Finding ID: {color(fid, 'bold')}")
        say(f"  State:      {color(curr_state, 'yellow')} -> {color('REJECTED', 'red')}")
        say(f"  Reason:     {reason}")
        return 0

    elif subcmd == "history":
        fid = args.finding_id
        f_dir = d / "findings" / fid
        timeline_p = f_dir / "timeline.json"
        if not timeline_p.exists():
            say(color(f"  [error] Finding '{fid}' history not found.", "red"))
            return 1

        tdata = json.loads(timeline_p.read_text(encoding="utf-8"))
        section(f"Finding History: {fid}")
        for entry in tdata:
            ts = entry.get("timestamp")
            fr = entry.get("from") or "Start"
            to = entry.get("to")
            rs = entry.get("reason")
            say(f"  [{ts}] {fr} -> {color(to, 'cyan')}")
            say(f"    Reason: {rs}\n")
        return 0

    elif subcmd in ("attach-evidence", "attach"):
        fid = args.finding_id
        eid = args.evidence_id

        f_dir = d / "findings" / fid
        f_json = f_dir / "finding.json"
        if not f_json.exists():
            say(color(f"  [error] Finding '{fid}' not found in engagement workspace.", "red"))
            return 1

        ev_root = d / "evidence"
        ev_found = False
        if ev_root.exists():
            for meta_p in ev_root.glob("*/metadata.json"):
                try:
                    items = json.loads(meta_p.read_text(encoding="utf-8"))
                    if any(item.get("evidence_id") == eid for item in items):
                        ev_found = True
                        break
                except Exception:
                    pass

        if not ev_found:
            say(color(f"  [error] Unknown evidence ID '{eid}'. Evidence does not exist in workspace.", "red"))
            return 1

        fdata = json.loads(f_json.read_text(encoding="utf-8"))
        ev_list = fdata.setdefault("evidence_ids", [])
        if eid not in ev_list:
            ev_list.append(eid)
            fdata["updated_at"] = datetime.datetime.now().isoformat()
            f_json.write_text(json.dumps(fdata, indent=2), encoding="utf-8")
            _sync_findings_index(d)

        section("Evidence Attached")
        say(f"  Finding ID:  {color(fid, 'bold')}")
        say(f"  Evidence ID: {color(eid, 'cyan')}")
        return 0

    elif subcmd == "hypothesis":
        hyp_cmd = args.hyp_subcommand
        fid = args.finding_id
        f_dir = d / "findings" / fid
        hyp_p = f_dir / "hypotheses.json"
        if not f_dir.exists():
            say(color(f"  [error] Finding '{fid}' not found in engagement workspace.", "red"))
            return 1

        hdata = json.loads(hyp_p.read_text(encoding="utf-8")) if hyp_p.exists() else []

        if hyp_cmd == "add":
            htype = _sanitize_sensitive(args.type or "IDOR")
            hdesc = _sanitize_sensitive(args.description or "Security hypothesis")
            hid = f"HY-{len(hdata) + 1:03d}"
            now_str = datetime.datetime.now().isoformat()
            hdata.append({
                "id": hid,
                "type": htype,
                "description": hdesc,
                "status": "testing",
                "created_at": now_str
            })
            hyp_p.write_text(json.dumps(hdata, indent=2), encoding="utf-8")
            section("Hypothesis Added")
            say(f"  Hypothesis ID: {color(hid, 'bold')}")
            say(f"  Finding ID:    {color(fid, 'cyan')}")
            say(f"  Type:          {htype}")
            say(f"  Description:   {hdesc}")
            return 0
        elif hyp_cmd == "list":
            section(f"Hypotheses for {fid}")
            if not hdata:
                say("  No hypotheses recorded.")
                return 0
            for h in hdata:
                say(f"  [{color(h.get('id'), 'bold')}] Type: {h.get('type')} | Status: {h.get('status')}")
                say(f"    Description: {h.get('description')}\n")
            return 0

    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    d = _get_eng_dir()
    _sync_findings_index(d)
    findings_file = d / "findings.json"
    if not findings_file.exists():
        say(color("  No findings recorded in engagement workspace.", "yellow"))
        return 0

    try:
        findings = json.loads(findings_file.read_text(encoding="utf-8"))
    except Exception as e:
        say(color(f"  [error] Malformed findings.json file: {e}", "red"))
        return 1

    section("Confirmed Engagement Findings")
    if not findings:
        say("  No findings recorded yet.")
        return 0

    for f in findings:
        fid = f.get("finding_id", "FH-UNKNOWN")
        title = f.get("title", "Untitled")
        sev = f.get("severity", "Info")
        ep = f.get("endpoint", "N/A")
        st = f.get("status", "HYPOTHESIS")
        say(f"  [{color(fid, 'bold')}] {color(title, 'cyan')} ({color(sev, 'yellow')}) [{color(st, 'bold')}]")
        say(f"      Endpoint: {ep} | CWE: {f.get('CWE', 'N/A')} | VRT: {f.get('VRT', 'N/A')}")
    return 0








def cmd_monitor(args: argparse.Namespace) -> int:
    """Interact with NYX Continuous Monitoring Engine."""
    subcmd = getattr(args, "monitor_subcommand", None)
    from nyx.application.continuous_service import ContinuousService
    svc = ContinuousService()

    if subcmd == "start":
        target = getattr(args, "target", "example.com")
        res = svc.start_monitoring_job(target=target)
        say(color(f"Continuous monitoring job started for '{target}'.", "green"))
        say(json.dumps(res.data, indent=2))
        return 0
    elif subcmd == "status":
        res = svc.get_monitoring_status()
        say(color("NYX Active Monitoring Jobs:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    say(color("Usage: nyx monitor [start <target>|status]", "yellow"))
    return 1


def cmd_assets(args: argparse.Namespace) -> int:
    """Interact with NYX Asset Intelligence History."""
    subcmd = getattr(args, "assets_subcommand", None)
    from nyx.application.continuous_service import ContinuousService
    svc = ContinuousService()

    if subcmd == "history":
        res = svc.get_asset_history()
        say(color("NYX Asset History Snapshots:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    say(color("Usage: nyx assets [history]", "yellow"))
    return 1


def cmd_changes(args: argparse.Namespace) -> int:
    """Interact with NYX Security Change Detection."""
    subcmd = getattr(args, "changes_subcommand", None)
    from nyx.application.continuous_service import ContinuousService
    svc = ContinuousService()

    if subcmd == "list":
        res = svc.list_changes()
        say(color("NYX Security Change Events:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    say(color("Usage: nyx changes [list]", "yellow"))
    return 1


def cmd_alerts(args: argparse.Namespace) -> int:
    """Interact with NYX Alert Manager."""
    subcmd = getattr(args, "alerts_subcommand", None)
    from nyx.application.continuous_service import ContinuousService
    svc = ContinuousService()

    if subcmd == "list":
        res = svc.list_alerts()
        say(color("NYX Active Security Alerts:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    say(color("Usage: nyx alerts [list]", "yellow"))
    return 1


def cmd_research(args: argparse.Namespace) -> int:
    """Interact with NYX Research Opportunity Engine."""
    subcmd = getattr(args, "research_subcommand", None)
    from nyx.application.continuous_service import ContinuousService
    svc = ContinuousService()

    if subcmd == "opportunities":
        res = svc.list_research_opportunities()
        say(color("NYX Prioritized Research Opportunities:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    say(color("Usage: nyx research [opportunities]", "yellow"))
    return 1


def cmd_browser(args: argparse.Namespace) -> int:
    """Interact with NYX Browser Automation Engine."""
    subcmd = getattr(args, "browser_subcommand", None)
    from nyx.application.browser_service import BrowserService
    svc = BrowserService()

    if subcmd == "start":
        target = getattr(args, "target", "example.com")
        res = svc.start_session(target=target)
        say(color(f"Browser session started for target '{target}'.", "green"))
        say(json.dumps(res.data, indent=2))
        return 0
    elif subcmd == "sessions":
        res = svc.list_sessions()
        say(color("NYX Stored & Active Browser Sessions:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    say(color("Usage: nyx browser [start <target>|sessions]", "yellow"))
    return 1


def cmd_runtime(args: argparse.Namespace) -> int:
    """Interact with NYX Runtime Intelligence Engine."""
    subcmd = getattr(args, "runtime_subcommand", None)
    from nyx.application.browser_service import BrowserService
    svc = BrowserService()

    if subcmd == "events":
        res = svc.get_runtime_intelligence()
        say(color("NYX Runtime Intelligence Graph:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    say(color("Usage: nyx runtime [events]", "yellow"))
    return 1


def cmd_auth(args: argparse.Namespace) -> int:
    """Interact with NYX Authentication Intelligence."""
    subcmd = getattr(args, "auth_subcommand", None)
    from nyx.application.browser_service import BrowserService
    svc = BrowserService()

    if subcmd == "flows":
        res = svc.list_auth_flows()
        say(color("NYX Authentication Intelligence State:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    say(color("Usage: nyx auth [flows]", "yellow"))
    return 1


def cmd_workers(args: argparse.Namespace) -> int:
    """Interact with NYX Distributed Worker Nodes."""
    subcmd = getattr(args, "workers_subcommand", None)
    from nyx.application.worker_service import WorkerService
    svc = WorkerService()

    if subcmd == "list":
        res = svc.list_workers()
        say(color("NYX Registered Worker Nodes:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0
    elif subcmd == "register":
        hostname = getattr(args, "hostname", "worker-1")
        res = svc.register_worker(hostname=hostname)
        say(color(f"Registered worker node '{res.data.get('worker_id')}' ({hostname}).", "green"))
        return 0
    elif subcmd == "status":
        res = svc.get_worker_status()
        say(color("NYX Worker Fleet Status:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0
    elif subcmd == "remove":
        worker_id = getattr(args, "worker_id", "")
        res = svc.remove_worker(worker_id)
        if res.is_success:
            say(color(f"Removed worker node '{worker_id}'.", "yellow"))
            return 0
        else:
            say(color(f"Error: {res.error}", "red"))
            return 1
    elif subcmd == "run":
        interval = float(getattr(args, "interval", 1.0))
        once = bool(getattr(args, "once", False))
        worker_id = getattr(args, "worker_id", None)
        hostname = getattr(args, "hostname", None)
        server_url = getattr(args, "server_url", None)
        api_token = getattr(args, "api_token", None)

        say(color("Starting NYX Worker Execution Runtime...", "bold"))
        res = svc.start_daemon(
            poll_interval=interval,
            once=once,
            worker_id=worker_id,
            hostname=hostname,
            server_url=server_url,
            api_token=api_token,
        )
        say(color(f"Worker runtime finished processing {res.data.get('processed_tasks_count')} task(s).", "green"))
        return 0

    say(color("Usage: nyx workers [list|register|status|remove|run]", "yellow"))
    return 1


def cmd_agents(args: argparse.Namespace) -> int:
    """Interact with NYX Multi-Agent Fleet."""
    subcmd = getattr(args, "agents_subcommand", None)
    from nyx.application.fleet_service import FleetService
    svc = FleetService()

    if subcmd == "list":
        res = svc.list_agents()
        say(color("NYX Active Specialized Agents:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0
    elif subcmd == "create":
        atype = getattr(args, "type", "recon")
        target = getattr(args, "target", "example.com")
        res = svc.create_agent(type=atype, target=target)
        say(color(f"Created agent '{res.data.get('agent_id')}' of type '{atype}' for '{target}'.", "green"))
        return 0
    elif subcmd == "stop":
        agent_id = getattr(args, "agent_id", "")
        res = svc.stop_agent(agent_id)
        if res.is_success:
            say(color(f"Stopped agent '{agent_id}'.", "yellow"))
            return 0
        else:
            say(color(f"Error: {res.error}", "red"))
            return 1

    say(color("Usage: nyx agents [list|create|stop]", "yellow"))
    return 1


def cmd_tasks(args: argparse.Namespace) -> int:
    """Interact with NYX Distributed Task Queue."""
    from nyx.application.fleet_service import FleetService
    svc = FleetService()
    res = svc.list_tasks()
    say(color("NYX Distributed Task Queue:", "bold"))
    say(json.dumps(res.data, indent=2))
    return 0


def cmd_fleet(args: argparse.Namespace) -> int:
    """Show complete NYX Multi-Agent Fleet Status."""
    subcmd = getattr(args, "fleet_subcommand", None)
    from nyx.application.fleet_service import FleetService
    svc = FleetService()

    if subcmd == "status" or not subcmd:
        res = svc.get_fleet_status()
        say(color("NYX Multi-Agent Fleet Status:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    """Interact with NYX Autonomous Security Research Agent."""
    subcmd = getattr(args, "agent_subcommand", None)
    from nyx.application.agent_service import AgentService
    svc = AgentService()

    if subcmd == "start":
        target = getattr(args, "target", "example.com")
        res = svc.start_mission(target)
        say(color(f"NYX Agent mission started for target '{target}'. State: {res.data.get('agent_state')}", "cyan"))
        return 0
    elif subcmd == "context":
        target = getattr(args, "target", "example.com")
        res = svc.get_context(target)
        say(color(f"NYX Agent Reasoning Context for '{target}':", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0
    elif subcmd == "plan":
        target = getattr(args, "target", "example.com")
        res = svc.plan_mission(target)
        say(color(f"NYX Autonomous Research Plan for '{target}':", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0
    elif subcmd == "approvals":
        res = svc.get_approvals()
        if not res.is_success:
            say(color(f"Error: {res.error}", "red"))
            return 1
        data = res.data or {}
        pending = data.get("pending", [])
        say(color(f"NYX Pending Action Approvals ({len(pending)} pending):", "bold"))
        if not pending:
            say("  No pending approvals.")
            return 0
        for item in pending:
            aid = item.get("action_id", "UNKNOWN")
            tgt = item.get("target", "unknown")
            act = item.get("action", "unknown")
            tool = item.get("tool_name") or item.get("tool") or "unknown"
            impact = item.get("impact_class", "UNKNOWN")
            just = item.get("impact_justification", "")
            say(f"  • {color(aid, 'yellow')} [{color(impact, 'red' if impact == 'DESTRUCTIVE' else 'green')}] {tool} -> {act}")
            say(f"    Target: {tgt}")
            if just:
                say(f"    Justification: {just}")
        return 0
    elif subcmd == "approve":
        action_id = getattr(args, "action_id", "")
        res = svc.approve_action(action_id)
        if res.is_success:
            say(color(f"Action '{action_id}' approved and executed successfully.", "green"))
            exec_res = res.data.get("execution_result") if isinstance(res.data, dict) else None
            if exec_res:
                tool_used = exec_res.get("tool")
                status_v = exec_res.get("result", {}).get("status") if isinstance(exec_res.get("result"), dict) else "completed"
                say(f"  Tool: {tool_used} | Status: {status_v}")
            return 0
        else:
            say(color(f"Error: {res.error}", "red"))
            return 1
    elif subcmd == "deny":
        action_id = getattr(args, "action_id", "")
        reason = getattr(args, "reason", "")
        res = svc.deny_action(action_id, reason=reason)
        if res.is_success:
            say(color(f"Action '{action_id}' denied successfully.", "yellow"))
            return 0
        else:
            say(color(f"Error: {res.error}", "red"))
            return 1
    elif subcmd == "status":
        res = svc.get_status()
        say(color("NYX Agent Status:", "bold"))
        say(json.dumps(res.data, indent=2))
        return 0

    say(color("Usage: nyx agent [start|context|plan|approvals|approve|deny|status]", "yellow"))
    return 1


def cmd_web(args: argparse.Namespace) -> int:
    """Launch NYX Security Operations Dashboard & Web Platform."""
    from nyx.infrastructure.dependencies import BootstrapManager, DependencyProfile
    boot_mgr = BootstrapManager()
    boot_mgr.ensure_environment(profile=DependencyProfile.WEB)

    host = getattr(args, "host", "0.0.0.0")
    port = getattr(args, "port", 8000)
    
    from nyx.web.auth import get_or_create_api_token
    token = get_or_create_api_token()

    dashboard_host = "localhost" if host in ("0.0.0.0", "0:0:0:0:0:0:0:0", "::") else host

    say(color("=" * 60, "cyan"))
    say(color(" NYX Security Operations Dashboard", "bold"))
    say(color("=" * 60, "cyan"))
    say(f" API Server:    http://{host}:{port}")
    say(f" Dashboard:     http://{dashboard_host}:{port}")
    say(f" WebSocket:     ws://{dashboard_host}:{port}/ws/events")
    say(f" API Docs:      http://{dashboard_host}:{port}/api/docs")
    say(f" Authentication: ENABLED (Token configured)")
    say(f" API Token:     {token[:8]}...{token[-4:]}")
    from nyx.infrastructure.logging import setup_logging
    setup_logging()

    import uvicorn
    uvicorn.run("nyx.web.app:app", host=host, port=port, reload=False)
    return 0


def cmd_ai(args: argparse.Namespace) -> int:
    from nyx.application.ai_service import AIService
    service = AIService()

    subcmd = getattr(args, "ai_subcommand", None) or getattr(args, "subcmd", None)
    target = getattr(args, "target", "") or ""

    if sys.argv and "ai" in sys.argv:
        idx = sys.argv.index("ai")
        rem = [a for a in sys.argv[idx+1:] if not a.startswith("--")]
        if len(rem) >= 1:
            if rem[0] == "test":
                subcmd = "test"
                # Do not overwrite 'target' with rem[1] for 'test'; rely on argparse
            else:
                subcmd = rem[0]
                if len(rem) >= 2:
                    target = rem[1]

    if subcmd == "providers":
        res = service.list_providers()
        if not res.is_success:
            say(color(f"  [error] {res.error}", "red"))
            return 1
        section("NYX Registered AI Providers")
        active = res.data.get("active")
        for p_item in res.data.get("providers", []):
            mark = "* " if p_item.get("name") == active else "  "
            p_name = p_item.get("name", "")
            p_type = p_item.get("type", "")
            p_stat = p_item.get("status", "")
            p_err = p_item.get("error", "")

            stat_color = "green" if p_stat == "ready" else ("yellow" if p_stat == "unavailable" else "red")
            stat_str = p_stat
            if p_stat == "unavailable" and p_err:
                if "SDK" in p_err:
                    stat_str = "unavailable - SDK missing"
                elif "not configured" in p_err:
                    stat_str = "unavailable - API key not configured"
            say(f"{mark}{color(p_name, 'bold'):<12} Type: {p_type:<20} Status: {color(stat_str, stat_color)}")
        return 0

    elif subcmd == "context":
        if not target:
            target = "example.com"
        res = service.get_context(target)
        if not res.is_success:
            say(color(f"  [error] {res.error}", "red"))
            return 1
        data = res.data
        section(f"NYX Security Context — {target}")
        say(f"Target:       {color(data.get('target', ''), 'cyan')}")
        say(f"In Scope:     {data.get('in_scope')}")
        say(f"Phase:        {data.get('phase')}")
        say(f"Technologies: {', '.join(data.get('technologies', [])) or 'None'}")
        say(f"Endpoints:    {len(data.get('endpoints', []))} recorded")
        say(f"Skills:       {len(data.get('skills', []))} matched")
        return 0

    elif subcmd == "plan":
        if not target:
            say(color("  [error] Target is required for planning (e.g. nyx ai plan example.com)", "red"))
            return 1
        provider = getattr(args, "provider", None)
        if not provider and sys.argv and "--provider" in sys.argv:
            try:
                p_idx = sys.argv.index("--provider")
                if p_idx + 1 < len(sys.argv):
                    provider = sys.argv[p_idx + 1]
            except Exception:
                pass
        res = service.plan_mission(target, provider_name=provider)
        if not res.is_success:
            say(color(f"  [error] {res.error}", "red"))
            return 1
        plan = res.data
        section(f"NYX Recommended AI Mission Plan — {target}")
        say(f"Provider:          {color(plan.get('provider', ''), 'bold')}")
        say(f"Phase:             {plan.get('phase')}")
        rec_foc = plan.get('recommended_focus', '')
        if rec_foc == "AI analysis unavailable":
            say(f"Recommended Focus: {color(rec_foc, 'yellow')}")
        else:
            say(f"Recommended Focus: {color(rec_foc, 'cyan')}")
        if plan.get("analysis"):
            say(f"Analysis:          {plan.get('analysis')}")
        say("")
        say("Recommended Mission:")
        for step in plan.get("steps", []):
            perm = color("[PERMITTED]", "green") if step.get("permitted") else color("[BLOCKED]", "red")
            say(f"  {step.get('step')}. {color(step.get('name', ''), 'bold')} ({step.get('action')}) {perm}")
            say(f"     Tool: {step.get('tool')} | Description: {step.get('description')}")

        if getattr(args, "execute", False) or (sys.argv and "--execute" in sys.argv):
            say("")
            say(color("Auto-Executing Mission Plan with Tool Harness & Validation Bridge...", "bold"))
            exec_res = service.execute_mission(target, provider_name=provider, active_permitted=True)
            if not exec_res.is_success:
                say(color(f"  [error] {exec_res.error}", "red"))
                return 1
            exec_data = exec_res.data or {}
            say(color(f"✓ Plan Execution Complete: {exec_data.get('executed_steps', 0)} steps executed.", "green"))
            for s_res in exec_data.get("step_results", []):
                s_tool = s_res.get("tool", "")
                s_name = s_res.get("name", "")
                s_meta = s_res.get("result", {})
                fids = s_meta.get("metadata", {}).get("findings_created", []) if isinstance(s_meta, dict) else []
                if fids:
                    say(f"   [+] {s_name} ({s_tool}): {len(fids)} validated findings -> {', '.join(fids)}")

        return 0

    elif subcmd == "execute":
        if not target:
            say(color("  [error] Target is required for execution (e.g. nyx ai execute example.com)", "red"))
            return 1
        active_perm = getattr(args, "active_permitted", False) or ("--active-permitted" in sys.argv if sys.argv else False)
        provider = getattr(args, "provider", None)
        if not provider and sys.argv and "--provider" in sys.argv:
            try:
                p_idx = sys.argv.index("--provider")
                if p_idx + 1 < len(sys.argv):
                    provider = sys.argv[p_idx + 1]
            except Exception:
                pass
        res = service.execute_mission(target, provider_name=provider, active_permitted=active_perm)
        if not res.is_success:
            say(color(f"  [error] {res.error}", "red"))
            return 1
        exec_data = res.data or {}
        section(f"NYX AI Mission Execution — {target}")
        say(f"Target:         {color(target, 'cyan')}")
        say(f"Executed Steps: {exec_data.get('executed_steps', 0)}")
        say("")
        say("Step Execution Results:")
        for step in exec_data.get("step_results", []):
            step_num = step.get("step", "")
            step_name = step.get("name", "")
            tool_name = step.get("tool", "")
            step_res = step.get("result", {})

            stat_summary = "COMPLETED"
            if isinstance(step_res, dict):
                status_val = step_res.get("status", "")
                if step_res.get("dry_run"):
                    stat_summary = f"{status_val or 'COMPLETED'} (dry-run)"
                elif status_val == "skipped":
                    stat_summary = f"skipped — {step_res.get('reason', 'no pending findings')}"
                elif "classified_count" in step_res:
                    stat_summary = f"success — classified {step_res.get('classified_count')} endpoint(s)"
                elif "category" in step_res:
                    stat_summary = f"success — category: {step_res.get('category')}"
                elif "triaged_count" in step_res:
                    stat_summary = f"success — triaged {step_res.get('triaged_count')} finding(s)"
                elif status_val:
                    stat_summary = status_val

            stat_color = "green" if ("success" in stat_summary.lower() or "completed" in stat_summary.lower()) else ("yellow" if "skipped" in stat_summary.lower() else "red")
            tool_str = f" [Tool: {tool_name}]" if tool_name else ""
            say(f"  {step_num}. {color(step_name, 'bold')}{tool_str}")
            say(f"     Status: {color(stat_summary, stat_color)}")
        return 0

    elif subcmd == "test":
        target_prov = target or "gemini"
        res = service.test_provider(provider_name=target_prov)
        data = res.data or {}
        msg = data.get("message") or res.error or "Test completed"
        section(f"NYX AI Provider Test — {target_prov.upper()}")
        say(f"Provider:  {color(data.get('provider', target_prov), 'bold')}")
        say(f"Model:     {data.get('model', 'default')}")
        say(f"Status:    {color(data.get('status', 'unknown'), 'green' if res.is_success else 'red')}")
        say(f"Message:   {msg}")
        if data.get("sample"):
            say(f"Sample:    {data.get('sample')}")
        return 0 if res.is_success else 1

    elif subcmd == "status":
        res = service.get_status()
        if not res.is_success:
            say(color(f"  [error] {res.error}", "red"))
            return 1
        data = res.data
        section("NYX AI Integration Status")
        say(f"Active Provider:    {color(data.get('active_provider', ''), 'bold')}")
        say(f"Available Providers:{', '.join(data.get('registered_providers', []))}")
        say(f"Recent Decisions:   {data.get('recent_decisions_count')}")
        say(f"Failed Approaches:  {data.get('failed_approaches_count')}")
        return 0

    elif subcmd == "autonomous":
        if not target:
            say(color("  [error] Target is required for autonomous mission (e.g. nyx ai autonomous example.com)", "red"))
            return 1

        active_perm = getattr(args, "active_permitted", False)
        if sys.argv and "--active-permitted" in sys.argv:
            active_perm = True

        provider = getattr(args, "provider", None)
        if not provider and sys.argv and "--provider" in sys.argv:
            try:
                p_idx = sys.argv.index("--provider")
                if p_idx + 1 < len(sys.argv):
                    provider = sys.argv[p_idx + 1]
            except Exception:
                pass

        max_iter = getattr(args, "max_iterations", 15)
        if sys.argv and "--max-iterations" in sys.argv:
            try:
                m_idx = sys.argv.index("--max-iterations")
                if m_idx + 1 < len(sys.argv):
                    max_iter = int(sys.argv[m_idx + 1])
            except Exception:
                pass

        is_json = getattr(args, "json", False) or (sys.argv and "--json" in sys.argv)

        res = service.planner.run_autonomous_loop(
            target=target,
            provider_name=provider,
            active_permitted=active_perm,
            max_iterations=max_iter,
        )

        if is_json:
            print(json.dumps(res, indent=2))
            return 0 if res.get("status") != "error" else 1

        status_val = res.get("status", "unknown")
        status_color = "green" if status_val in ("complete", "success") else ("yellow" if status_val in ("paused_for_approval", "escalated") else "red")

        section(f"NYX AI Autonomous Mission Loop — {target}")
        say(f"Target:          {color(target, 'cyan')}")
        say(f"Loop Status:     {color(status_val.upper(), status_color)}")
        say(f"Iterations Run:  {len(res.get('iterations', []))}")

        if status_val == "paused_for_approval":
            p_step = res.get("pending_step", {})
            say("")
            say(color(f"  [PAUSED] Destructive Step Pending Approval: {p_step.get('name')} ({p_step.get('tool')})", "yellow"))
            say(f"  Impact: {p_step.get('impact_justification', 'Modifies system/database state')}")
        elif status_val == "escalated":
            e_step = res.get("escalated_step", {})
            say("")
            say(color(f"  [ESCALATED] Strategic Escalation Triggered on: {e_step.get('name')}", "yellow"))
        elif status_val == "blocked":
            b_step = res.get("blocked_step", {})
            say("")
            say(color(f"  [BLOCKED] Policy Blocked Step: {b_step.get('name')}", "red"))
        elif status_val == "ai_unavailable":
            say("")
            say(color(f"  [AI PROVIDER UNAVAILABLE] Autonomous mission halted at iteration {res.get('iteration_halted', len(res.get('iterations', [])) + 1)}", "red"))
            say(f"  Reason: {color(res.get('error') or res.get('degradation_reason') or 'AI decision engine failed', 'yellow')}")
            say(color("  Safety Enforcement: No further steps executed. No unverified findings generated.", "yellow"))
        elif status_val == "error":
            say("")
            say(color(f"  [ERROR] {res.get('error', 'Execution error')}", "red"))
            return 1

        if res.get("iterations"):
            say("")
            say("Execution Timeline:")
            for it in res["iterations"]:
                it_idx = it.get("iteration")
                s = it.get("step", {})
                r = it.get("result", {})
                r_status = r.get("status") if isinstance(r, dict) else "completed"
                say(f"  [{it_idx}] {color(s.get('name', 'Step'), 'bold')} ({s.get('tool')}) -> {r_status}")

        return 0

    say(color("  [error] Unknown AI subcommand. Supported: providers, test [provider], context, plan <target>, execute <target>, autonomous <target>, status", "red"))
    return 1



def cmd_duplicate_check(args: argparse.Namespace) -> int:
    d = _get_eng_dir()
    findings_file = d / "findings.json"

    ep = normalize_url(args.endpoint or "").lower()
    param = (args.parameter or "").strip().lower()
    vuln = (args.vulnerability or "").strip().lower()

    if not findings_file.exists():
        say(color("  No duplicate found (findings database is empty).", "green"))
        return 0

    try:
        findings = json.loads(findings_file.read_text(encoding="utf-8"))
    except Exception as e:
        say(color(f"  [error] Malformed findings.json: {e}", "red"))
        return 1

    for f in findings:
        f_ep = normalize_url(str(f.get("endpoint", ""))).lower()
        f_param = str(f.get("parameter", "")).strip().lower()
        f_vuln = str(f.get("vulnerability", "")).strip().lower()

        if f_ep == ep and f_param == param and f_vuln == vuln:
            section("Duplicate Finding Warning")
            say(color("  [WARNING] Possible duplicate finding detected!", "yellow"))
            say(f"  Existing Finding ID: {f.get('finding_id')}")
            say(f"  Title:               {f.get('title')}")
            say(f"  Endpoint:            {f_ep}")
            say(f"  Parameter:           {f_param}")
            say(f"  Vulnerability:       {f_vuln}")
            return 1

    say(color("  [PASS] No duplicate finding detected for this vector.", "green"))
    return 0


def calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file for evidence integrity checking."""
    import hashlib
    if not file_path.exists():
        return ""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _get_evidence_dir(finding_id: str, create: bool = True) -> tuple[Path | None, str]:
    """Resolve and optionally initialize .engagement/evidence/<finding_id>/ directory structure."""
    d = _get_eng_dir()
    if not d.exists():
        return None, "No active engagement workspace found (.engagement/)."

    findings_file = d / "findings.json"
    findings = []
    if findings_file.exists():
        try:
            findings = json.loads(findings_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    known_fids = {f.get("finding_id") for f in findings if f.get("finding_id")}
    ev_base = d / "evidence" / finding_id

    if finding_id not in known_fids and not ev_base.exists():
        return None, f"Finding '{finding_id}' does not exist in current engagement."

    if create:
        ev_base.mkdir(parents=True, exist_ok=True)
        (ev_base / "requests").mkdir(exist_ok=True)
        (ev_base / "responses").mkdir(exist_ok=True)
        (ev_base / "attachments").mkdir(exist_ok=True)
        notes_file = ev_base / "notes.md"
        if not notes_file.exists():
            notes_file.write_text(f"# Evidence Notes — {finding_id}\n\n", encoding="utf-8")
        meta_file = ev_base / "metadata.json"
        if not meta_file.exists():
            meta_file.write_text("[]", encoding="utf-8")

    return ev_base, "OK"


def _generate_evidence_id(eng_dir: Path, year: int | None = None) -> str:
    """Generate unique evidence ID (EV-YYYY-XXXX)."""
    if year is None:
        year = datetime.datetime.now().year
    ev_root = eng_dir / "evidence"
    max_seq = 0
    if ev_root.exists():
        for meta_p in ev_root.glob("*/metadata.json"):
            try:
                items = json.loads(meta_p.read_text(encoding="utf-8"))
                for item in items:
                    eid = item.get("evidence_id", "")
                    if eid.startswith(f"EV-{year}-"):
                        seq_str = eid.split("-")[-1]
                        if seq_str.isdigit():
                            max_seq = max(max_seq, int(seq_str))
            except Exception:
                pass
    return f"EV-{year}-{max_seq + 1:04d}"





def cmd_mission(args: argparse.Namespace) -> int:
    from nyx.api.mission import init_mission, status_mission, run_mission
    subcmd = getattr(args, "mission_subcommand", None)
    if subcmd == "init":
        return init_mission(args.target, reset=getattr(args, "reset", False))
    elif subcmd == "status":
        return status_mission()
    elif subcmd == "run":
        return run_mission(args.target, provider=getattr(args, "provider", None))
    return 0


def cmd_knowledge(args: argparse.Namespace) -> int:
    from nyx.core.knowledge import search_knowledge
    subcmd = getattr(args, "knowledge_subcommand", None)
    if subcmd == "search":
        kw = args.keyword
        res = search_knowledge(keyword=kw)
        section(f"NYX Knowledge Base Search: '{kw}'")
        match_techs = res.get("matched_technologies", [])
        match_vulns = res.get("matched_vulnerabilities", [])
        skills = res.get("matched_skills", [])
        intent = res.get("primary_intent", "vulnerability")

        def print_vulns():
            if match_vulns:
                say(color("Matched Vulnerability Knowledge:", "yellow"))
                for v in match_vulns:
                    v_obj = v.get("vulnerability", {})
                    say(f"  • {color(v_obj.get('name', 'N/A'), 'bold')} [{v_obj.get('category')}]: {v_obj.get('description', '')}")

        def print_techs():
            if match_techs:
                say(color("Matched Technologies:", "cyan"))
                for t in match_techs:
                    t_obj = t.get("technology", {})
                    say(f"  • {color(t_obj.get('name', 'N/A'), 'bold')}: {t_obj.get('description', '')}")

        if intent == "vulnerability":
            print_vulns()
            if match_vulns and match_techs:
                say("")
            print_techs()
        else:
            print_techs()
            if match_techs and match_vulns:
                say("")
            print_vulns()

        if skills:
            say(color("\nRecommended Security Skills:", "green"))
            for sk in skills:
                say(f"  - {sk}")
        if not match_techs and not match_vulns and not skills:
            say("  No matching records found in NYX Knowledge Base.")
        return 0
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from nyx.application.analysis_service import AnalysisService
    service = AnalysisService()
    subcmd = getattr(args, "analyze_subcommand", None)

    if subcmd == "context":
        d = _get_eng_dir()
        t_name = getattr(args, "target", None)
        if not t_name and d.exists():
            t_file = d / "target.yaml"
            if t_file.exists():
                for line in t_file.read_text(encoding="utf-8").splitlines():
                    if line.strip().startswith("domain:") or line.strip().startswith("name:"):
                        t_name = line.split(":", 1)[1].strip().strip('"').strip("'")
                        break
        target = t_name
        url = getattr(args, "url", None)
        res = service.get_decision_context(url=url or f"https://{target or 'example.com'}/login.aspx")
        if target and not url:
            res["target"] = target
        t_name = res.get("target", target or "example.com")
        ep_scope = res.get("endpoint", url or f"https://{t_name}/login.aspx")
        techs = res.get("technologies", [])
        skills = res.get("recommended_skills", [])
        graph = res.get("graph", {})

        section(f"NYX Intelligence Decision Context — {t_name}")
        say(f"Target Domain:    {color(t_name, 'cyan')}")
        say(f"Endpoint Scope:   {ep_scope}")
        say(f"Detected Stack:   {', '.join(techs) if techs else 'None recorded'}\n")
        say("Recommended Security Skills:")
        for sk in skills:
            say(f"  • {color(sk, 'bold')}")
        if graph:
            say("\nAttack Surface Graph:")
            say(f"  • Node Count: {graph.get('nodes_count', len(graph.get('nodes', [])))}")
            say(f"  • Edge Count: {graph.get('edges_count', len(graph.get('edges', [])))}")
        say(color("=" * 50, "cyan"))
        return 0

    elif subcmd == "surface":
        d = _get_eng_dir()
        t_name = getattr(args, "target", None)
        if not t_name and d.exists():
            t_file = d / "target.yaml"
            if t_file.exists():
                for line in t_file.read_text(encoding="utf-8").splitlines():
                    if line.strip().startswith("domain:") or line.strip().startswith("name:"):
                        t_name = line.split(":", 1)[1].strip().strip('"').strip("'")
                        break
        target = t_name or "example.com"
        manifest = getattr(args, "manifest", None)
        res = service.rank_surface(target, manifest=manifest)
        if res.get("status") == "error":
            say(color(f"  [error] {res.get('error')}", "red"))
            return 1
        section(f"NYX Attack Surface Ranking — {target}")
        for item in res.get("rankings", []):
            say(f"  • [{color(str(item.get('score', '')), 'bold')}] {item.get('endpoint', '')} — {item.get('reason', '')}")
        return 0

    return 0


def cmd_skills(args: argparse.Namespace) -> int:
    from nyx.core.skills import load_skills, search_skills, get_skill
    from nyx.core.router import recommend_skills
    subcmd = getattr(args, "skills_subcommand", None)

    if subcmd == "list":
        skills_map = load_skills()
        section(f"NYX Registered Security Skills ({len(skills_map)} total)")
        for name, info in sorted(skills_map.items()):
            say(f"  • {color(name, 'bold')} [{info['category']}] — {info['description'][:80]}...")
        return 0
    elif subcmd == "search":
        kw = args.keyword
        matches = search_skills(kw)
        section(f"NYX Skill Search Results for '{kw}' ({len(matches)} matches)")
        for sk in matches:
            say(f"  • {color(sk['name'], 'bold')} [{sk['category']}]: {sk['description'][:100]}")
        return 0
    elif subcmd == "show":
        s_name = args.skill_name
        sk = get_skill(s_name)
        if not sk:
            say(color(f"  [error] Skill '{s_name}' not found.", "red"))
            return 1
        section(f"NYX Skill Details: {sk['name']}")
        say(f"Category:     {sk['category']}")
        say(f"Technologies: {', '.join(sk['technology'])}\n")
        say(f"Description:\n{sk['description']}\n")
        say("Validation Requirements:")
        for r in sk.get("validation_requirements", []):
            say(f"  - {r}")
        return 0
    elif subcmd == "recommend":
        url = args.url
        rec = recommend_skills(url, technology=getattr(args, "technology", None))
        section(f"Skill Recommendations for: {url}")
        say(f"Priority: {color(rec.get('priority', 'MEDIUM'), 'yellow')}")
        say(f"Surfaces: {', '.join(rec.get('attack_surface', []))}\n")
        say("Recommended Skills:")
        for sk in rec.get("recommended_skills", []):
            say(f"  - {color(sk, 'bold')}")
        return 0
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    from nyx.validation.engine import validate_finding
    from nyx.validation.rules import get_rule, VALIDATION_RULES

    f_id = getattr(args, "finding_id", None)
    v_type = getattr(args, "type_name", None)
    subcmd = getattr(args, "validate_subcommand", None)

    # Check for direct 'nyx validate rules <type>' invocation
    if sys.argv and len(sys.argv) >= 4 and sys.argv[1] == "validate" and sys.argv[2] == "rules":
        v_type = sys.argv[3]
    elif f_id == "rules" and v_type is None and len(sys.argv) >= 4:
        v_type = sys.argv[3]

    if v_type:
        rule = get_rule(v_type)
        if not rule:
            say(color(f"  [error] Validation rule for '{v_type}' not found.", "red"))
            return 1
        section(f"NYX Validation Rule Specification: {rule['type']}")
        say(f"Category: {rule['category']}")
        say(f"Base Confidence: {rule['base_confidence']}%\n")
        say("Required Evidence:")
        for req in rule['required_evidence']:
            say(f"  • {req}")
        say("\nValidation Checklist:")
        for chk in rule['checklist']:
            say(f"  ✓ {chk}")
        say("\nRejection Conditions:")
        for rej in rule['rejection_conditions']:
            say(f"  ✗ {rej}")
        return 0

    if f_id:
        res = validate_finding(f_id)
        val = res.get("validation", {})
        section("NYX Validation Report")
        say(f"Finding:\n{res.get('title') or f_id}\n")
        say(f"Confidence:\n{val.get('confidence', 0)}%\n")
        say("Passed:")
        for p in val.get("passed", []):
            say(f"✓ {p}")
        if val.get("missing"):
            say("\nMissing:")
            for m in val.get("missing", []):
                say(f"! {m}")
        say(f"\nStatus:\n{color(val.get('status', 'NEEDS VALIDATION'), 'yellow' if val.get('status') == 'NEEDS VALIDATION' else 'green')}")
        return 0

    return 0


def cmd_exec(args: argparse.Namespace) -> int:
    from nyx.application.execution_service import ExecutionService
    service = ExecutionService()

    tool_name = getattr(args, "tool", "") or ""
    target = getattr(args, "target", "") or ""
    subcmd = getattr(args, "exec_subcommand", None)

    # Handle sys.argv for flags passed before positional arguments
    if sys.argv and "exec" in sys.argv:
        idx = sys.argv.index("exec")
        remaining = [a for a in sys.argv[idx+1:] if not a.startswith("--")]
        if len(remaining) >= 3 and remaining[0] in ("run", "status", "history"):
            subcmd = remaining[0]
            tool_name = remaining[1]
            target = remaining[2]
        elif len(remaining) == 2:
            if remaining[0] == "run":
                subcmd = "run"
                tool_name = remaining[1]
            elif remaining[0] in ("status", "history"):
                subcmd = remaining[0]
                target = remaining[1]
            else:
                tool_name, target = remaining[0], remaining[1]
        elif len(remaining) == 1:
            if remaining[0] in ("status", "history"):
                subcmd = remaining[0]
            else:
                tool_name = remaining[0]

    dry_run = getattr(args, "dry_run", False) or "--dry-run" in sys.argv

    if tool_name == "status" or subcmd == "status":
        eid = target or getattr(args, "execution_id", "")
        if not eid:
            say(color("  [error] Execution ID is required (e.g. nyx exec status EXEC-XXXXXXXX). Use 'nyx exec history' to see recent execution IDs.", "red"))
            return 1
        res = service.get_status(eid)
        if not res.is_success:
            say(color(f"  [error] {res.error}", "red"))
            return 1
        data = res.data
        res_info = data.get("result", {})
        section(f"NYX Tool Execution Status: {eid}")
        say(f"Tool:       {res_info.get('tool_name') or res_info.get('tool')}")
        say(f"Target:     {res_info.get('target')}")
        say(f"Class:      {res_info.get('execution_class')}")
        say(f"Exit Code:  {res_info.get('exit_code')}")
        say(f"Authorized: {res_info.get('authorized')}")
        say(f"Scope:      {res_info.get('scope_status')}")
        say(f"Dry-Run:    {res_info.get('dry_run')}")
        return 0

    elif tool_name == "history" or subcmd == "history":
        section("NYX Tool Execution History")
        res = service.get_history()
        history = res.data.get("history", [])
        if history:
            for it in history:
                dry = "[DRY-RUN] " if it.get("dry_run") else ""
                t_name = it.get("tool_name") or it.get("tool")
                say(f"  • {color(it.get('execution_id'), 'bold')} {dry}{t_name} ➔ {it.get('target')} [{it.get('execution_class')}] Code: {it.get('exit_code')}")
            return 0
        say("  No execution history recorded in active workspace.")
        return 0

    if tool_name == "run":
        tool_name = target
        target = getattr(args, "extra_target", "") or ""

    if not tool_name or not target:
        say(color("  [error] Please specify tool and target (e.g. nyx exec subfinder example.com)", "red"))
        return 1

    svc_res = service.run_tool(tool_name, target, dry_run=dry_run)
    res_data = svc_res.to_dict()
    res = res_data.get("data", {})

    section(f"NYX Tool Execution Result — {tool_name}")
    say(f"Execution ID: {color(res.get('execution_id', ''), 'bold')}")
    say(f"Target:       {color(res.get('target', ''), 'cyan')}")
    say(f"Class:        {res.get('execution_class', 'SAFE_ACTIVE')}")
    say(f"Authorized:   {color(str(res.get('authorized', False)), 'green' if res.get('authorized') else 'red')}")
    say(f"Scope Status: {color(res.get('scope_status', ''), 'green' if res.get('scope_status') == 'IN_SCOPE' else 'yellow')}")
    say(f"Dry-Run:      {res.get('dry_run', False)}")
    say(f"Exit Code:    {res.get('exit_code', 1)}")

    if res.get("stdout"):
        say("Output:")
        say(res.get("stdout")[:1000])
    if res.get("stderr") and res.get("exit_code") != 0:
        say(color(f"Error Output: {res.get('stderr')[:500]}", "red"))

    meta = res.get("metadata") or {}
    if isinstance(meta, dict) and meta.get("warning"):
        say(color(f"Warning: {meta.get('warning')}", "yellow"))

    return 0 if (res.get("dry_run") or res.get("exit_code") == 0) else 1


def cmd_surface(args: argparse.Namespace) -> int:
    from nyx.application.analysis_service import AnalysisService
    service = AnalysisService()
    target = getattr(args, "target", "")
    manifest = getattr(args, "manifest", None)
    res = service.rank_surface(target, manifest=manifest)
    if res.get("status") == "error":
        say(color(f"  [error] {res.get('message') or res.get('error')}", "red"))
        return 1
    section(f"NYX Attack Surface Ranking — {target}")
    for item in res.get("rankings", []):
        say(f"  • [{color(str(item.get('score', '')), 'bold')}] {item.get('endpoint', '')} — {item.get('reason', '')}")
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    from nyx.application.analysis_service import AnalysisService
    service = AnalysisService()
    url = getattr(args, "url", "")
    burp = getattr(args, "burp", False)
    proxy = getattr(args, "proxy", None)
    res = service.classify_url(url, burp=burp, proxy=proxy)
    section(f"NYX Endpoint Classification — {url}")
    say(f"Category: {color(res.get('category', 'UNCLASSIFIED'), 'cyan')}")
    say("Recommended Skills:")
    for sk in res.get("skills", []):
        say(f"  • {color(sk, 'bold')}")
    return 0


def cmd_technology_map(args: argparse.Namespace) -> int:
    from nyx.application.analysis_service import AnalysisService
    service = AnalysisService()
    tech = getattr(args, "technology", "")
    res = service.technology_map(tech)
    if res.get("status") == "error":
        say(color(f"  [error] {res.get('error')}", "red"))
        return 1
    section(f"NYX Technology Attack Map — {tech}")
    say(f"Category: {res.get('category')}")
    say("Attack Vectors:")
    for vec in res.get("vectors", []):
        say(f"  • {color(vec.get('name', ''), 'bold')}: {vec.get('description', '')}")
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    from nyx.application.evidence_service import EvidenceService
    service = EvidenceService()
    subcmd = getattr(args, "ev_subcommand", "") or getattr(args, "evidence_subcommand", "")

    if subcmd == "add":
        fid = getattr(args, "finding_id", "")
        ev_type = getattr(args, "type", "note")
        content = getattr(args, "content", None)
        file_path = getattr(args, "file", None)
        desc = getattr(args, "description", "")
        src = getattr(args, "source", "manual")
        res = service.add(finding_id=fid, ev_type=ev_type, content=content, file=file_path, description=desc, source=src)
        if res.get("status") == "error":
            say(color(f"  [error] {res.get('message', 'Failed to add evidence')}", "red"))
            return 1
        say(color(f"✓ Added evidence {res.get('evidence_id')} to {fid} (SHA256: {res.get('sha256', '')[:8]})", "green"))
        return 0
    elif subcmd == "list":
        fid = getattr(args, "finding_id", "")
        res = service.list_evidence(fid)
        if res.get("status") == "error":
            say(color(f"  [error] {res.get('message', 'Failed to list evidence')}", "red"))
            return 1
        section(f"NYX Evidence Vault — {fid}")
        ev_list = res.get("evidence", [])
        if not ev_list:
            say("  No evidence found.")
            return 0
        for ev in ev_list:
            eid = ev.get('evidence_id', '')
            etype = ev.get('type', '')
            desc = ev.get('description', '')
            h = ev.get('sha256', '')
            integ = ev.get('integrity', 'PASS')
            say(f"  • {color(eid, 'bold')} [{etype}] — {desc} (Hash: {h[:8]}..., Integrity: {color(integ, 'green' if integ == 'PASS' else 'red')})")
        return 0
    elif subcmd == "show":
        eid = getattr(args, "evidence_id", "")
        res = service.show(eid)
        if res.get("status") == "error":
            say(color(f"  [error] {res.get('message', res.get('error', 'Unknown error'))}", "red"))
            return 1
        item = res.get("evidence", {})
        section(f"NYX Evidence Details — {eid}")
        say(f"Finding ID:  {item.get('finding_id')}")
        say(f"Type:        {item.get('type')}")
        say(f"Source:      {item.get('source')}")
        say(f"Description: {item.get('description')}")
        say(f"SHA256:      {item.get('sha256')}")
        say(f"File:        {item.get('file')}")
        if res.get("preview_lines"):
            say("\nContent Preview:")
            for line in res.get("preview_lines", []):
                say(f"  {line}")
        return 0
    elif subcmd == "verify":
        eid = getattr(args, "evidence_id", "")
        res = service.verify(eid)
        if res.get("status") == "error":
            say(color(f"  [error] {res.get('message', 'Failed to verify evidence')}", "red"))
            return 1
        if res.get("integrity") == "PASS":
            say(color(f"✓ Evidence {eid} integrity verified ({res.get('current_hash', '')[:8]}).", "green"))
            return 0
        else:
            say(color(f"✗ Evidence {eid} integrity check FAILED: expected {res.get('expected_hash')[:8]} but got {res.get('current_hash')[:8]}", "red"))
            return 1
    return 1


def cmd_triage(args: argparse.Namespace) -> int:
    from nyx.application.finding_service import FindingService
    service = FindingService()
    path = getattr(args, "finding", "")
    res = service.triage_finding(path)
    section("NYX 7-Question Quality Gate Triage")
    say(f"Finding: {path}")
    say(f"Score:   {res.get('passed_count', 0)}/7")
    say(f"Status:  {color(res.get('status', ''), 'green' if res.get('status') == 'PASSED' else 'red')}\n")
    for q in res.get("questions", []):
        mark = "✓" if q.get("passed") else "✗"
        col = "green" if q.get("passed") else "red"
        say(f"  {color(mark, col)} {q.get('id')}: {q.get('question')}")
    return 0 if res.get("status") == "PASSED" else 1


def cmd_report(args: argparse.Namespace) -> int:
    from nyx.application.finding_service import FindingService
    service = FindingService()
    path = getattr(args, "finding", "")
    platform = getattr(args, "platform", "bugcrowd")
    out = getattr(args, "out", None)
    res = service.report_finding(path, platform=platform, out=out)
    if res.get("status") == "error":
        err_msg = res.get("error") or res.get("message") or "Report generation failed."
        say(color(f"  [error] {err_msg}", "red"))
        return 1
    if res.get("report_path"):
        say(color(f"✓ Generated {platform.capitalize()} report at {res.get('report_path')}", "green"))
    else:
        say(color(f"✓ Generated {platform.capitalize()} report:", "green"))
    if res.get("draft"):
        say(res.get("draft"))
    return 0


VERSION = "1.0.0"
APP_NAME = "NYX Security Intelligence Engine"


# ============================================================
# Main dispatcher
# ============================================================

def cmd_doctor(args: argparse.Namespace) -> int:
    import platform
    from nyx.infrastructure.dependencies import BootstrapManager, DependencyProfile
    from nyx.infrastructure.environment import PlatformInfo

    boot_mgr = BootstrapManager()
    checks = boot_mgr.run_preflight_checks(profile=DependencyProfile.WEB)

    section("NYX Security Intelligence Engine Environment Doctor")
    
    say("System")
    say(f"  OS              ✓ {PlatformInfo.get_os().upper()}")
    say(f"  Architecture    ✓ {platform.machine()}")

    say("\nPython")
    say(f"  Version         ✓ {PlatformInfo.get_python_version()}")
    py_check = next((c for c in checks if c["name"] == "pip"), {})
    say(f"  pip             {'✓' if py_check.get('status') == 'OK' else '✗'}")

    say("\nPython Packages")
    pkg_check = next((c for c in checks if c["name"] == "Python packages"), {})
    say(f"  NYX             ✓")
    say(f"  FastAPI         {'✓' if pkg_check.get('status') == 'OK' else '✗'}")
    say(f"  Uvicorn         {'✓' if pkg_check.get('status') == 'OK' else '✗'}")

    say("\nFrontend")
    node_check = next((c for c in checks if c["name"] == "Node.js"), {})
    npm_check = next((c for c in checks if c["name"] == "npm"), {})
    dep_check = next((c for c in checks if c["name"] == "Frontend deps"), {})
    build_check = next((c for c in checks if c["name"] == "Frontend build"), {})

    say(f"  Node.js         {'✓ ' + node_check.get('detail', '') if node_check.get('status') in ('OK', 'WARN') else '✗ NOT FOUND'}")
    say(f"  npm             {'✓ ' + npm_check.get('detail', '') if npm_check.get('status') == 'OK' else '✗ NOT FOUND'}")
    say(f"  Dependencies    {'✓' if dep_check.get('status') == 'OK' else '✗ MISSING'}")
    say(f"  Build           {'✓' if build_check.get('status') == 'OK' else '✗ MISSING'}")

    say("\nAI Providers")
    from nyx.ai.providers.gemini import HAS_GENAI
    gemini_key_set = bool(os.environ.get("GEMINI_API_KEY"))
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    say(f"  Gemini SDK       {'✓ Installed' if HAS_GENAI else '✗ Not installed (pip install google-genai)'}")
    say(f"  Gemini API Key   {'✓ Configured in current process' if gemini_key_set else '✗ Not configured in current process'}")
    say(f"  Gemini Model     ✓ {gemini_model}")

    from nyx.ai.providers.grok import HAS_XAI_SDK
    grok_key_set = bool(os.environ.get("XAI_API_KEY"))
    grok_model = os.environ.get("XAI_MODEL", "grok-4.6")

    say(f"  Grok SDK         {'✓ Installed' if HAS_XAI_SDK else '✗ Not installed (pip install openai)'}")
    say(f"  Grok API Key     {'✓ Configured in current process' if grok_key_set else '✗ Not configured in current process'}")
    say(f"  Grok Model       ✓ {grok_model}")

    from nyx.ai.providers.groq import HAS_GROQ_SDK
    groq_key_set = bool(os.environ.get("GROQ_API_KEY"))
    groq_model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

    say(f"  Groq SDK         {'✓ Installed' if HAS_GROQ_SDK else '✗ Not installed (pip install openai)'}")
    say(f"  Groq API Key     {'✓ Configured in current process' if groq_key_set else '✗ Not configured in current process'}")
    say(f"  Groq Model       ✓ {groq_model}")

    if not gemini_key_set:
        curr_os = PlatformInfo.get_os()
        say(color(f"\n  [info] Current environment: {curr_os.upper()}", "yellow"))
        if curr_os == "windows":
            say(color("  GEMINI_API_KEY is not available to this process.", "yellow"))
            say("  Configure it in the environment used to launch NYX (PowerShell: $env:GEMINI_API_KEY=\"<key>\")")
        elif curr_os == "wsl2":
            say(color("  GEMINI_API_KEY is not available to this WSL process.", "yellow"))
            say("  Export it in WSL (export GEMINI_API_KEY=\"<key>\") before launching NYX.")
        else:
            say(color("  GEMINI_API_KEY is not available to this process.", "yellow"))
            say("  Export it (export GEMINI_API_KEY=\"<key>\") before launching NYX.")

    say("\nSecurity")
    target_file = REPO_ROOT / ".engagement" / "target.yaml"
    say(f"  Workspace       {'✓ PRESENT' if target_file.exists() else '✓ READY'}")
    say(f"  Configuration   ✓ OK")

    skills_count = len(list(SKILLS_DIR.glob("*.md"))) if SKILLS_DIR.exists() else 0
    agents_skills = REPO_ROOT / ".agents" / "skills"
    skills_count += len(list(agents_skills.rglob("*.md"))) if agents_skills.exists() else 0
    say(f"\nLoaded Security Skills: {skills_count}")

    say(color("\nResult:\n✓ NYX environment is ready", "green"))
    return 0


def build_parser(prog_name: str = "nyx") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog_name,
        description=f"{APP_NAME} - Antigravity-native terminal runner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""Examples:
  {prog_name} engagement init example.com
  {prog_name} engagement status
  {prog_name} state ANALYSIS
  {prog_name} state --mode research
  {prog_name} memory import-burp history.xml
  {prog_name} evidence list EV-2026-001
  {prog_name} evidence show EV-2026-0001
  {prog_name} evidence verify EV-2026-0001
  {prog_name} technology map graphql
  {prog_name} duplicate-check --endpoint /api/v1/user --parameter id --vulnerability IDOR
  {prog_name} recon hackerone.com
  {prog_name} classify "https://api.target.com/v1/users/42?next=https://evil.com"
  {prog_name} triage findings/idor-2026-05-15.md
  {prog_name} report findings/idor-2026-05-15.md --platform bugcrowd --out draft.md
""",
    )
    parser.add_argument("--version", "-v", action="version", version=f"{APP_NAME}\nVersion: {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_proxy_args(p):
        p.add_argument("--burp", action="store_true",
                       help="Route HTTP through Burp Suite proxy (auto-detects 127.0.0.1:8080)")
        p.add_argument("--proxy", help="Explicit proxy URL (overrides --burp)")
    # Existing commands
    p_doctor = sub.add_parser("doctor", help="diagnose environment, skills, and workspace readiness")
    p_doctor.set_defaults(func=cmd_doctor)

    p_recon = sub.add_parser("recon", help="passive recon + live-host probe + summary")
    p_recon.add_argument("target", help="root domain or subcommand (intelligence, js, api, parameters)")
    p_recon.add_argument("extra_arg", nargs="?", help="subcommand target domain or URL")
    p_recon.add_argument("--out", help="output directory for recon/<target>/")
    _add_proxy_args(p_recon)
    p_recon.set_defaults(func=cmd_recon)

    p_surface = sub.add_parser("surface", help="rank a target's attack surface from its recon manifest")
    p_surface.add_argument("target", help="target whose recon/<target>/manifest.json to read")
    p_surface.add_argument("--manifest", help="explicit path to a manifest.json")
    p_surface.set_defaults(func=cmd_surface)

    p_class = sub.add_parser("classify", help="pattern-match URL to hunt-* skills")
    p_class.add_argument("url", help="single URL to classify")
    _add_proxy_args(p_class)
    p_class.set_defaults(func=cmd_classify)

    p_triage = sub.add_parser("triage", help="run 7-Question Gate on a finding")
    p_triage.add_argument("finding", help="path to finding markdown file")
    p_triage.set_defaults(func=cmd_triage)

    p_report = sub.add_parser("report", help="emit a report draft")
    p_report.add_argument("finding", help="path to finding markdown file")
    p_report.add_argument("--platform", default="h1", choices=["h1", "bugcrowd", "intigriti", "immunefi"])
    p_report.add_argument("--out", help="write draft to this path (else print to stdout)")
    p_report.set_defaults(func=cmd_report)

    # Subcommands for Stage 2 & Stage 3 & Phase 4.1
    p_eng = sub.add_parser("engagement", help="manage persistent engagement workspace")
    p_eng.add_argument("eng_subcommand", choices=["init", "status", "export"])
    p_eng.add_argument("target", nargs="?", help="target domain (for init)")
    p_eng.add_argument("--reset", action="store_true", help="reset engagement workspace for a new target")
    p_eng.add_argument("--force", action="store_true", help="force reset engagement workspace")
    p_eng.set_defaults(func=cmd_engagement)

    p_mem = sub.add_parser("memory", help="add or search persistent engagement memory")
    p_mem_sub = p_mem.add_subparsers(dest="mem_subcommand", required=True)
    
    p_mem_add = p_mem_sub.add_parser("add", help="add item to memory")
    p_mem_add.add_argument("--type", choices=["endpoint", "technology", "vector", "note"], default="note")
    p_mem_add.add_argument("--value", required=True, help="value to record")
    p_mem_add.add_argument("--category", default="frameworks", help="technology category")
    p_mem_add.add_argument("--priority", default="P2", help="endpoint priority")
    p_mem_add.set_defaults(func=cmd_memory)

    p_mem_imp = p_mem_sub.add_parser("import-burp", help="import Burp Suite HTTP history XML with scope enforcement")
    p_mem_imp.add_argument("file", help="path to Burp history XML file")
    p_mem_imp.add_argument("--include-out-of-scope", action="store_true", help="administrative override to include out-of-scope endpoints")
    p_mem_imp.set_defaults(func=cmd_memory)

    p_mem_search = p_mem_sub.add_parser("search", help="search engagement memory")
    p_mem_search.add_argument("query", help="search query term")
    p_mem_search.set_defaults(func=cmd_memory)

    p_mem_list = p_mem_sub.add_parser("list", help="list items in persistent engagement memory")
    p_mem_list.add_argument("--type", choices=["all", "endpoint", "technology", "vector", "note"], default="all", help="memory type filter")
    p_mem_list.set_defaults(func=cmd_memory)

    p_ev = sub.add_parser("evidence", help="manage finding evidence storage")
    p_ev_sub = p_ev.add_subparsers(dest="ev_subcommand", required=True)

    p_ev_list = p_ev_sub.add_parser("list", help="list evidence associated with a finding")
    p_ev_list.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_ev_list.set_defaults(func=cmd_evidence)

    p_ev_show = p_ev_sub.add_parser("show", help="show evidence item details")
    p_ev_show.add_argument("evidence_id", help="evidence ID (e.g. EV-2026-0001)")
    p_ev_show.set_defaults(func=cmd_evidence)

    p_ev_verify = p_ev_sub.add_parser("verify", help="verify evidence file integrity")
    p_ev_verify.add_argument("evidence_id", help="evidence ID (e.g. EV-2026-0001)")
    p_ev_verify.set_defaults(func=cmd_evidence)

    p_ev_add = p_ev_sub.add_parser("add", help="add evidence item to a finding")
    p_ev_add.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_ev_add.add_argument("--type", choices=["http_request", "http_response", "note", "screenshot", "attachment"], default="note")
    p_ev_add.add_argument("--content", help="text content for evidence")
    p_ev_add.add_argument("--file", help="path to evidence file")
    p_ev_add.add_argument("--description", default="", help="evidence description")
    p_ev_add.add_argument("--source", default="manual", help="evidence source")
    p_ev_add.set_defaults(func=cmd_evidence)

    p_st = sub.add_parser("state", help="view or set workflow state (DISCOVERY, ANALYSIS, VALIDATION, REPORTING)")
    p_st.add_argument("new_state", nargs="?", choices=VALID_STATES, help="new state to set")
    p_st.add_argument("--mode", choices=["research", "strict"], help="set workflow execution mode (research or strict)")
    p_st.add_argument("--force-state", action="store_true", help="administrative state override flag")
    p_st.set_defaults(func=cmd_state)

    p_tm = sub.add_parser("technology", help="technology attack surface mapping")
    p_tm_sub = p_tm.add_subparsers(dest="tech_subcommand", required=True)
    p_tm_map = p_tm_sub.add_parser("map", help="show technology attack map")
    p_tm_map.add_argument("technology", nargs="?", help="technology name (e.g. graphql, react, aws)")
    p_tm_map.set_defaults(func=cmd_technology_map)

    p_find = sub.add_parser("findings", help="list confirmed findings")
    p_find.set_defaults(func=cmd_findings)

    # nyx mission subparsers
    p_mis = sub.add_parser("mission", help="run or manage automated security research missions")
    p_mis_sub = p_mis.add_subparsers(dest="mission_subcommand", required=True)

    p_mis_init = p_mis_sub.add_parser("init", help="initialize a mission workspace")
    p_mis_init.add_argument("target", help="target domain")
    p_mis_init.add_argument("--reset", action="store_true", help="reset workspace if existing target differs")
    p_mis_init.set_defaults(func=cmd_mission)

    p_mis_stat = p_mis_sub.add_parser("status", help="show active mission status")
    p_mis_stat.set_defaults(func=cmd_mission)

    p_mis_run = p_mis_sub.add_parser("run", help="run end-to-end security research mission")
    p_mis_run.add_argument("target", help="target domain")
    p_mis_run.add_argument("--provider", default=None, help="AI provider to use (gemini, grok, groq, claude, openai, local). Defaults to active provider.")
    p_mis_run.set_defaults(func=cmd_mission)

    # nyx run-mission top-level parser
    p_run_mis = sub.add_parser("run-mission", help="run end-to-end automated security research mission with live validation")
    p_run_mis.add_argument("target", help="target domain or URL")
    p_run_mis.add_argument("--provider", default=None, help="AI provider to use (gemini, grok, groq, claude, openai, local). Defaults to active provider.")
    p_run_mis.set_defaults(func=lambda args: cmd_mission(argparse.Namespace(mission_subcommand="run", target=args.target, provider=getattr(args, "provider", None))))

    # nyx knowledge subparsers
    p_kno = sub.add_parser("knowledge", help="search or inspect NYX Security Knowledge Base")
    p_kno_sub = p_kno.add_subparsers(dest="knowledge_subcommand", required=True)

    p_kno_src = p_kno_sub.add_parser("search", help="search knowledge base by keyword or technology")
    p_kno_src.add_argument("keyword", help="search term (e.g. aspnet, sqli, auth)")
    p_kno_src.set_defaults(func=cmd_knowledge)

    # nyx analyze subparsers
    p_anz = sub.add_parser("analyze", help="analyze target security context and attack surface")
    p_anz_sub = p_anz.add_subparsers(dest="analyze_subcommand", required=True)

    p_anz_ctx = p_anz_sub.add_parser("context", help="display security intelligence context for target")
    p_anz_ctx.add_argument("target", nargs="?", help="target domain")
    p_anz_ctx.add_argument("--url", help="specific target endpoint URL")
    p_anz_ctx.set_defaults(func=cmd_analyze)

    p_anz_srf = p_anz_sub.add_parser("surface", help="display prioritized attack surface ranking")
    p_anz_srf.add_argument("target", nargs="?", help="target domain")
    p_anz_srf.set_defaults(func=cmd_analyze)

    # nyx skills subparsers
    p_skl = sub.add_parser("skills", help="intelligent security skill routing and recommendations")
    p_skl_sub = p_skl.add_subparsers(dest="skills_subcommand", required=True)

    p_skl_lst = p_skl_sub.add_parser("list", help="list all registered security skills")
    p_skl_lst.set_defaults(func=cmd_skills)

    p_skl_src = p_skl_sub.add_parser("search", help="search skills by keyword or category")
    p_skl_src.add_argument("keyword", help="search term")
    p_skl_src.set_defaults(func=cmd_skills)

    p_skl_shw = p_skl_sub.add_parser("show", help="show skill details and validation requirements")
    p_skl_shw.add_argument("skill_name", help="skill name (e.g. hunt-auth-bypass)")
    p_skl_shw.set_defaults(func=cmd_skills)

    p_skl_rec = p_skl_sub.add_parser("recommend", help="recommend security skills for target endpoint URL")
    p_skl_rec.add_argument("url", help="target endpoint URL")
    p_skl_rec.add_argument("--technology", help="technology stack (e.g. ASP.NET, React)")
    p_skl_rec.set_defaults(func=cmd_skills)

    # nyx validate subparser
    p_val = sub.add_parser("validate", help="validate finding hypotheses and verify empirical evidence")
    p_val.add_argument("finding_id", nargs="?", help="finding ID or subcommand (rules)")
    p_val.add_argument("type_name", nargs="?", help="vulnerability type name for rules")
    p_val.set_defaults(func=cmd_validate)

    # nyx exec subparser
    p_exc = sub.add_parser("exec", help="execute or dry-run security tool in controlled environment")
    p_exc.add_argument("tool", nargs="?", help="tool name (e.g. subfinder, httpx, nuclei) or subcommand (status, history)")
    p_exc.add_argument("target", nargs="?", help="target domain or URL or execution ID")
    p_exc.add_argument("--dry-run", action="store_true", help="dry-run command generation without execution")
    p_exc.set_defaults(func=cmd_exec)

    # nyx finding lifecycle subparsers
    p_fnd = sub.add_parser("finding", help="manage finding research lifecycle and state machine")
    p_fnd_sub = p_fnd.add_subparsers(dest="finding_subcommand", required=True)

    p_fnd_create = p_fnd_sub.add_parser("create", help="create a new finding in HYPOTHESIS state")
    p_fnd_create.add_argument("--title", required=True, help="finding title")
    p_fnd_create.add_argument("--endpoint", help="vulnerable endpoint")
    p_fnd_create.add_argument("--parameter", help="vulnerable parameter")
    p_fnd_create.add_argument("--vulnerability", help="vulnerability classification")
    p_fnd_create.add_argument("--severity", choices=["Low", "Medium", "High", "Critical"], help="finding severity")
    p_fnd_create.add_argument("--description", help="finding initial description")
    p_fnd_create.add_argument("--tag", action="append", help="tags (can be specified multiple times)")
    p_fnd_create.set_defaults(func=cmd_finding)

    p_fnd_list = p_fnd_sub.add_parser("list", help="list all findings")
    p_fnd_list.set_defaults(func=cmd_finding)

    p_fnd_show = p_fnd_sub.add_parser("show", help="show details for a finding")
    p_fnd_show.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_fnd_show.set_defaults(func=cmd_finding)

    p_fnd_trans = p_fnd_sub.add_parser("transition", help="transition finding state")
    p_fnd_trans.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_fnd_trans.add_argument("new_state", choices=VALID_FINDING_STATES, help="new state to set")
    p_fnd_trans.add_argument("--reason", required=True, help="reason for state transition")
    p_fnd_trans.set_defaults(func=cmd_finding)

    p_fnd_rej = p_fnd_sub.add_parser("reject", help="reject a finding hypothesis")
    p_fnd_rej.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_fnd_rej.add_argument("--reason", required=True, help="reason for rejecting finding")
    p_fnd_rej.set_defaults(func=cmd_finding)

    p_fnd_hist = p_fnd_sub.add_parser("history", help="show finding timeline history")
    p_fnd_hist.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_fnd_hist.set_defaults(func=cmd_finding)

    p_fnd_att = p_fnd_sub.add_parser("attach-evidence", help="attach an evidence ID to finding")
    p_fnd_att.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_fnd_att.add_argument("evidence_id", help="evidence ID (e.g. EV-2026-0001)")
    p_fnd_att.set_defaults(func=cmd_finding)

    p_fnd_att2 = p_fnd_sub.add_parser("attach", help="alias for attach-evidence")
    p_fnd_att2.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_fnd_att2.add_argument("evidence_id", help="evidence ID (e.g. EV-2026-0001)")
    p_fnd_att2.set_defaults(func=cmd_finding)

    p_fnd_hyp = p_fnd_sub.add_parser("hypothesis", help="manage finding hypotheses")
    p_fnd_hyp_sub = p_fnd_hyp.add_subparsers(dest="hyp_subcommand", required=True)

    p_fnd_hyp_add = p_fnd_hyp_sub.add_parser("add", help="add hypothesis to finding")
    p_fnd_hyp_add.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_fnd_hyp_add.add_argument("--type", default="IDOR", help="hypothesis type")
    p_fnd_hyp_add.add_argument("--description", required=True, help="hypothesis description")
    p_fnd_hyp_add.set_defaults(func=cmd_finding)

    p_fnd_hyp_list = p_fnd_hyp_sub.add_parser("list", help="list hypotheses for finding")
    p_fnd_hyp_list.add_argument("finding_id", help="finding ID (e.g. FH-2026-001)")
    p_fnd_hyp_list.set_defaults(func=cmd_finding)

    p_dup = sub.add_parser("duplicate-check", help="check finding for duplication")
    p_dup.add_argument("--endpoint", required=True, help="endpoint URL or path")
    p_dup.add_argument("--parameter", required=True, help="vulnerable parameter name")
    p_dup.add_argument("--vulnerability", required=True, help="vulnerability class name")
    p_dup.set_defaults(func=cmd_duplicate_check)

    # nyx agent subparsers
        # nyx agents subparsers
        # nyx workers subparsers
        # nyx browser subparsers
        # nyx monitor subparsers
    p_monitor = sub.add_parser("monitor", help="interact with NYX Continuous Monitoring")
    p_mon_sub = p_monitor.add_subparsers(dest="monitor_subcommand")
    p_mo_st = p_mon_sub.add_parser("start", help="start continuous monitoring job")
    p_mo_st.add_argument("target", help="target domain")
    p_mo_st.set_defaults(func=cmd_monitor)
    p_mo_stat = p_mon_sub.add_parser("status", help="show monitoring status")
    p_mo_stat.set_defaults(func=cmd_monitor)
    p_monitor.set_defaults(func=cmd_monitor)

    # nyx assets subparsers
    p_assets = sub.add_parser("assets", help="interact with NYX Asset Intelligence")
    p_ass_sub = p_assets.add_subparsers(dest="assets_subcommand")
    p_as_his = p_ass_sub.add_parser("history", help="show asset graph history")
    p_as_his.set_defaults(func=cmd_assets)
    p_assets.set_defaults(func=cmd_assets)

    # nyx changes subparsers
    p_changes = sub.add_parser("changes", help="interact with NYX Change Detection")
    p_chg_sub = p_changes.add_subparsers(dest="changes_subcommand")
    p_ch_lst = p_chg_sub.add_parser("list", help="list detected surface change events")
    p_ch_lst.set_defaults(func=cmd_changes)
    p_changes.set_defaults(func=cmd_changes)

    # nyx alerts subparsers
    p_alerts = sub.add_parser("alerts", help="interact with NYX Alerts")
    p_alt_sub = p_alerts.add_subparsers(dest="alerts_subcommand")
    p_al_lst = p_alt_sub.add_parser("list", help="list active security alerts")
    p_al_lst.set_defaults(func=cmd_alerts)
    p_alerts.set_defaults(func=cmd_alerts)

    # nyx research subparsers
    p_research = sub.add_parser("research", help="interact with NYX Research Opportunities")
    p_res_sub = p_research.add_subparsers(dest="research_subcommand")
    p_rs_opp = p_res_sub.add_parser("opportunities", help="list research recommendations")
    p_rs_opp.set_defaults(func=cmd_research)
    p_research.set_defaults(func=cmd_research)

    p_browser = sub.add_parser("browser", help="interact with NYX Browser Engine")
    p_browser_sub = p_browser.add_subparsers(dest="browser_subcommand")

    p_br_start = p_browser_sub.add_parser("start", help="start a new browser session")
    p_br_start.add_argument("target", help="target domain")
    p_br_start.set_defaults(func=cmd_browser)

    p_br_sess = p_browser_sub.add_parser("sessions", help="list active browser sessions")
    p_br_sess.set_defaults(func=cmd_browser)
    p_browser.set_defaults(func=cmd_browser)

    # nyx runtime subparsers
    p_runtime = sub.add_parser("runtime", help="interact with NYX Runtime Intelligence")
    p_runtime_sub = p_runtime.add_subparsers(dest="runtime_subcommand")
    p_rt_evt = p_runtime_sub.add_parser("events", help="show runtime intelligence graph & events")
    p_rt_evt.set_defaults(func=cmd_runtime)
    p_runtime.set_defaults(func=cmd_runtime)

    # nyx auth subparsers
    p_auth = sub.add_parser("auth", help="interact with NYX Authentication Intelligence")
    p_auth_sub = p_auth.add_subparsers(dest="auth_subcommand")
    p_au_flw = p_auth_sub.add_parser("flows", help="show authentication flows & session tokens")
    p_au_flw.set_defaults(func=cmd_auth)
    p_auth.set_defaults(func=cmd_auth)

    p_workers = sub.add_parser("workers", help="interact with NYX Distributed Worker Nodes")
    p_workers_sub = p_workers.add_subparsers(dest="workers_subcommand")

    p_wk_list = p_workers_sub.add_parser("list", help="list registered worker nodes")
    p_wk_list.set_defaults(func=cmd_workers)

    p_wk_reg = p_workers_sub.add_parser("register", help="register a new worker node")
    p_wk_reg.add_argument("--hostname", default="worker-1", help="worker hostname")
    p_wk_reg.set_defaults(func=cmd_workers)

    p_wk_stat = p_workers_sub.add_parser("status", help="show worker status & health metrics")
    p_wk_stat.set_defaults(func=cmd_workers)

    p_wk_rem = p_workers_sub.add_parser("remove", help="remove a worker node by ID")
    p_wk_rem.add_argument("worker_id", help="worker ID (e.g. WRK-12345678)")
    p_wk_rem.set_defaults(func=cmd_workers)

    p_wk_run = p_workers_sub.add_parser("run", help="start worker runtime to process queued tasks")
    p_wk_run.add_argument("--interval", type=float, default=1.0, help="polling interval in seconds")
    p_wk_run.add_argument("--once", action="store_true", help="process available tasks once and exit")
    p_wk_run.add_argument("--worker-id", default=None, help="worker ID override")
    p_wk_run.add_argument("--hostname", default=None, help="hostname override")
    p_wk_run.add_argument("--server-url", default=None, help="NYX Controller REST API base URL for remote worker mode")
    p_wk_run.add_argument("--api-token", default=None, help="API authentication token for remote worker mode")
    p_wk_run.set_defaults(func=cmd_workers)

    p_workers.set_defaults(func=cmd_workers)

    p_agents = sub.add_parser("agents", help="interact with NYX Multi-Agent Fleet")
    p_agents_sub = p_agents.add_subparsers(dest="agents_subcommand")

    p_ag_list = p_agents_sub.add_parser("list", help="list active agents in fleet")
    p_ag_list.set_defaults(func=cmd_agents)

    p_ag_create = p_agents_sub.add_parser("create", help="create specialized agent")
    p_ag_create.add_argument("type", help="agent type (recon|web|api|technology|validation|reporting)")
    p_ag_create.add_argument("target", help="target domain")
    p_ag_create.set_defaults(func=cmd_agents)

    p_ag_stop = p_agents_sub.add_parser("stop", help="stop active agent by ID")
    p_ag_stop.add_argument("agent_id", help="agent ID (e.g. AGT-RECON-123456)")
    p_ag_stop.set_defaults(func=cmd_agents)
    p_agents.set_defaults(func=cmd_agents)

    # nyx tasks parser
    p_tasks = sub.add_parser("tasks", help="interact with NYX Distributed Task Queue")
    p_tasks_sub = p_tasks.add_subparsers(dest="tasks_subcommand")
    p_ts_list = p_tasks_sub.add_parser("list", help="list task queue")
    p_ts_list.set_defaults(func=cmd_tasks)
    p_tasks.set_defaults(func=cmd_tasks)

    # nyx fleet parser
    p_fleet = sub.add_parser("fleet", help="show complete NYX Multi-Agent Fleet status")
    p_fleet_sub = p_fleet.add_subparsers(dest="fleet_subcommand")
    p_fl_stat = p_fleet_sub.add_parser("status", help="show fleet status")
    p_fl_stat.set_defaults(func=cmd_fleet)
    p_fleet.set_defaults(func=cmd_fleet)

    p_agent = sub.add_parser("agent", help="interact with NYX Autonomous Security Research Agent")
    p_agent_sub = p_agent.add_subparsers(dest="agent_subcommand")

    p_ag_start = p_agent_sub.add_parser("start", help="start autonomous research mission")
    p_ag_start.add_argument("target", help="target domain")
    p_ag_start.set_defaults(func=cmd_agent)

    p_ag_ctx = p_agent_sub.add_parser("context", help="show current reasoning context")
    p_ag_ctx.add_argument("target", nargs="?", default="example.com", help="target domain")
    p_ag_ctx.set_defaults(func=cmd_agent)

    p_ag_plan = p_agent_sub.add_parser("plan", help="generate research plan")
    p_ag_plan.add_argument("target", nargs="?", default="example.com", help="target domain")
    p_ag_plan.set_defaults(func=cmd_agent)

    p_ag_approvals = p_agent_sub.add_parser("approvals", help="list pending action approval requests")
    p_ag_approvals.set_defaults(func=cmd_agent)

    p_ag_app = p_agent_sub.add_parser("approve", help="approve execution of proposed action")
    p_ag_app.add_argument("action_id", help="action ID (e.g. ACT-12345678)")
    p_ag_app.set_defaults(func=cmd_agent)

    p_ag_deny = p_agent_sub.add_parser("deny", help="deny proposed action")
    p_ag_deny.add_argument("action_id", help="action ID (e.g. ACT-12345678)")
    p_ag_deny.add_argument("--reason", default="", help="reason for denial")
    p_ag_deny.set_defaults(func=cmd_agent)

    p_ag_stat = p_agent_sub.add_parser("status", help="show agent status & pending approval queue")
    p_ag_stat.set_defaults(func=cmd_agent)
    p_agent.set_defaults(func=cmd_agent)

    # nyx web parser
    p_web = sub.add_parser("web", help="launch NYX web dashboard & API server")
    p_web.add_argument("--host", default="0.0.0.0", help="host address to bind dashboard server (default: 0.0.0.0)")
    p_web.add_argument("--port", type=int, default=8000, help="port number to bind (default: 8000)")
    p_web.set_defaults(func=cmd_web)

    # nyx ai subparsers
    p_ai = sub.add_parser("ai", help="interact with NYX AI Agent integration & mission planner")
    p_ai_sub = p_ai.add_subparsers(dest="ai_subcommand")

    p_ai_prov = p_ai_sub.add_parser("providers", help="list registered AI providers")
    p_ai_prov.set_defaults(func=cmd_ai)

    p_ai_test = p_ai_sub.add_parser("test", help="run health check test for AI provider")
    p_ai_test.add_argument("target", nargs="?", default="gemini", help="provider name (e.g. gemini, grok, groq)")
    p_ai_test.set_defaults(func=cmd_ai)

    p_ai_ctx = p_ai_sub.add_parser("context", help="show target security context for AI reasoning")
    p_ai_ctx.add_argument("target", nargs="?", default="example.com", help="target domain")
    p_ai_ctx.set_defaults(func=cmd_ai)

    p_ai_plan = p_ai_sub.add_parser("plan", help="generate policy-validated AI mission plan")
    p_ai_plan.add_argument("target", help="target domain")
    p_ai_plan.add_argument("--provider", default=None, help="AI provider to use (gemini, openai, grok, groq, local, claude). Defaults to the active provider.")
    p_ai_plan.add_argument("--execute", action="store_true", help="automatically execute planned steps with live tool harness and validation")
    p_ai_plan.set_defaults(func=cmd_ai)

    p_ai_execute = p_ai_sub.add_parser("execute", help="execute a policy-validated AI mission plan")
    p_ai_execute.add_argument("target", help="target domain")
    p_ai_execute.add_argument("--provider", default=None, help="AI provider to use (gemini, openai, grok, groq, local, claude). Defaults to the active provider.")
    p_ai_execute.add_argument("--active-permitted", action="store_true", help="allow ACTIVE-class execution steps, not just dry-run")
    p_ai_execute.set_defaults(func=cmd_ai)

    p_ai_auto = p_ai_sub.add_parser("autonomous", help="run autonomous AI security mission loop")
    p_ai_auto.add_argument("target", help="target domain")
    p_ai_auto.add_argument("--provider", default=None, help="AI provider to use (gemini, openai, grok, groq, local, claude). Defaults to active provider.")
    p_ai_auto.add_argument("--active-permitted", action="store_true", default=False, help="allow ACTIVE-class execution steps, not just dry-run")
    p_ai_auto.add_argument("--max-iterations", type=int, default=15, help="maximum iterations for the autonomous loop (default: 15)")
    p_ai_auto.add_argument("--json", action="store_true", help="output raw JSON results")
    p_ai_auto.set_defaults(func=cmd_ai)

    p_ai_stat = p_ai_sub.add_parser("status", help="show NYX AI integration status")
    p_ai_stat.set_defaults(func=cmd_ai)
    p_ai.set_defaults(func=cmd_ai)

    return parser


def main(argv=None) -> int:
    try:
        load_dotenv(REPO_ROOT / ".env", override=False)
    except Exception:
        pass

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    prog_name = "nyx"
    if sys.argv and sys.argv[0]:
        base = Path(sys.argv[0]).stem.lower()
        if base in ("nyx", "nyx"):
            prog_name = base

    parser = build_parser(prog_name=prog_name)
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    # Enforce strict state command permissions
    cmd_name = getattr(args, "command", None)
    if cmd_name:
        ok, err_msg = check_state_permission(cmd_name, args)
        if not ok:
            say(color(err_msg, "red"))
            return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())