"""
NYX Context Engine
Aggregates structured security intelligence context for AI reasoning.
"""
from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.security.authorization import is_hostname_in_scope


def _matches_target_endpoint(ep_url: str, target: str) -> bool:
    """Check if an endpoint belongs to the target host/port and path prefix."""
    if not ep_url or not target:
        return False
    t_has_scheme = "://" in str(target)
    t_clean = str(target).strip().lower()
    if not t_has_scheme:
        t_clean = f"http://{t_clean}"
    t_p = urllib.parse.urlparse(t_clean)
    t_host = t_p.hostname or ""
    t_has_port = ":" in (t_p.netloc or "")
    t_port = t_p.port or (443 if t_p.scheme == "https" else 80)
    t_path = t_p.path.rstrip("/")

    e_clean = str(ep_url).strip().lower()
    if "://" not in e_clean:
        e_clean = f"http://{e_clean}"
    e_p = urllib.parse.urlparse(e_clean)
    e_host = e_p.hostname or ""
    e_port = e_p.port or (443 if e_p.scheme == "https" else 80)
    e_path = e_p.path.rstrip("/")

    host_match = (t_host == e_host)
    if not host_match and "." in t_host and not t_host.replace(".", "").isdigit():
        if t_host not in ("localhost", "127.0.0.1", "::1") and e_host.endswith("." + t_host):
            host_match = True

    if not host_match:
        return False
    if t_has_port:
        if t_port != e_port:
            return False
    elif t_has_scheme:
        if t_port != e_port:
            return False
    if t_path and not (e_path == t_path or e_path.startswith(t_path + "/")):
        return False
    return True


def _endpoint_relevance_score(url_str: str) -> int:
    """Score endpoint relevance for security analysis (higher = more relevant)."""
    score = 0
    u_lower = str(url_str).lower()
    parsed = urllib.parse.urlparse(u_lower if "://" in u_lower else f"http://{u_lower}")
    path = parsed.path
    query = parsed.query

    # Query parameters are highest value for injection testing
    if query and "=" in query:
        score += 100
        if any(k in query for k in ["id=", "user=", "query=", "search=", "page=", "cmd=", "file=", "url=", "redirect="]):
            score += 50

    # API / Auth / Dynamic indicators
    if any(k in path for k in ["/api/", "/rest/", "/graphql", "/auth", "/login", "/admin", "/user", "/account", "/v1/", "/v2/"]):
        score += 60

    # Static assets are deprioritized
    if any(path.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".map", ".txt", ".gif"]):
        score -= 80

    # Root / blank path
    if path in ("", "/") and not query:
        score -= 40

    return score


class ContextEngine:
    """Aggregates engagement state, target scope, technologies, endpoints, and findings into structured AI context."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir

    def get_target_context(self, target: str) -> Dict[str, Any]:
        """Build structured context dictionary for AI reasoning."""
        d = _get_eng_dir(create=False, base_dir=self.base_dir)

        # 1. Scope and State
        in_scope = is_hostname_in_scope(target, base_dir=self.base_dir)
        state_info = {}
        if d.exists():
            sf = d / "state.json"
            if sf.exists():
                try:
                    state_info = json.loads(sf.read_text(encoding="utf-8"))
                except Exception:
                    pass

        # 2. Technologies
        technologies = []
        if d.exists():
            tf = d / "technologies.json"
            if tf.exists():
                try:
                    tech_data = json.loads(tf.read_text(encoding="utf-8"))
                    if isinstance(tech_data, dict):
                        for cat, items in tech_data.items():
                            if isinstance(items, list):
                                technologies.extend(items)
                    elif isinstance(tech_data, list):
                        technologies = [t.get("name") if isinstance(t, dict) else str(t) for t in tech_data]
                except Exception:
                    pass

        # 3. Endpoints
        endpoints = []
        if d.exists():
            ef = d / "endpoints.json"
            if ef.exists():
                try:
                    ep_data = json.loads(ef.read_text(encoding="utf-8"))
                    if isinstance(ep_data, list):
                        endpoints = [ep.get("url") if isinstance(ep, dict) else str(ep) for ep in ep_data]
                except Exception:
                    pass

        # Target-aware scoping and relevance prioritization
        if target:
            target_scoped_endpoints = [ep for ep in endpoints if _matches_target_endpoint(ep, target)]
            target_scoped_endpoints.sort(key=_endpoint_relevance_score, reverse=True)
            scoped_endpoints = target_scoped_endpoints[:50]
        else:
            endpoints.sort(key=_endpoint_relevance_score, reverse=True)
            scoped_endpoints = endpoints[:50]

        # 4. Relevant Skills
        skills = []
        if d.exists():
            from nyx.core.skills import list_skills
            try:
                sk_data = list_skills()
                skills = [s.get("name") for s in sk_data if isinstance(s, dict)]
            except Exception:
                skills = ["hunt-auth-bypass", "hunt-sqli", "hunt-xss", "hunt-idor", "hunt-api-misconfig"]
        else:
            skills = ["hunt-auth-bypass", "hunt-sqli", "hunt-xss", "hunt-idor", "hunt-api-misconfig"]

        # 5. Findings
        findings = []
        if d.exists():
            ff = d / "findings.json"
            if not ff.exists():
                ff = d / "database" / "findings.json"
            if ff.exists():
                try:
                    all_findings = json.loads(ff.read_text(encoding="utf-8"))
                    if isinstance(all_findings, list):
                        findings = [
                            f
                            for f in all_findings
                            if isinstance(f, dict)
                            and (
                                not target
                                or _matches_target_endpoint(f.get("endpoint") or "", target)
                                or _matches_target_endpoint(f.get("target") or "", target)
                            )
                        ]
                except Exception:
                    pass

        # 6. Previous Failed Approaches
        failed_approaches = []
        if d.exists():
            mf = d / "ai_memory.json"
            if not mf.exists():
                mf = d / "database" / "ai_memory.json"
            if mf.exists():
                try:
                    mem = json.loads(mf.read_text(encoding="utf-8"))
                    failed_approaches = mem.get("failed_approaches", [])
                except Exception:
                    pass

        # 7. Tested Vectors
        tested_vectors = []
        if d.exists():
            vf = d / "tested_vectors.json"
            if vf.exists():
                try:
                    all_vectors = json.loads(vf.read_text(encoding="utf-8"))
                    if isinstance(all_vectors, list):
                        tested_vectors = [
                            tv
                            for tv in all_vectors
                            if isinstance(tv, dict)
                            and (
                                not target
                                or _matches_target_endpoint(tv.get("endpoint") or "", target)
                                or _matches_target_endpoint(tv.get("target") or "", target)
                            )
                        ]
                except Exception:
                    pass

        raw_context = {
            "target": target,
            "in_scope": in_scope,
            "phase": state_info.get("state", "DISCOVERY"),
            "mode": state_info.get("mode", "research"),
            "technologies": technologies,
            "endpoints": scoped_endpoints,
            "skills": skills[:20],
            "findings": findings,
            "previous_findings": findings,
            "failed_approaches": failed_approaches,
            "tested_vectors": tested_vectors,
        }

        # 8. Context-Aware Knowledge Retrieval
        from nyx.core.knowledge import retrieve_context_knowledge
        try:
            raw_context["relevant_knowledge"] = retrieve_context_knowledge(raw_context)
        except Exception:
            raw_context["relevant_knowledge"] = {
                "matched_technologies": [],
                "matched_vulnerabilities": [],
                "recommended_skills": [],
                "attack_surfaces": [],
                "related_cves": [],
            }

        return raw_context
