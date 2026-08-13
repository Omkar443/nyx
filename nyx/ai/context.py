"""
NYX Context Engine
Aggregates structured security intelligence context for AI reasoning.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.security.authorization import is_hostname_in_scope


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
                    if isinstance(tech_data, list):
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
            ff = d / "database" / "findings.json"
            if ff.exists():
                try:
                    findings = json.loads(ff.read_text(encoding="utf-8"))
                except Exception:
                    pass

        # 6. Previous Failed Approaches
        failed_approaches = []
        if d.exists():
            mf = d / "database" / "ai_memory.json"
            if mf.exists():
                try:
                    mem = json.loads(mf.read_text(encoding="utf-8"))
                    failed_approaches = mem.get("failed_approaches", [])
                except Exception:
                    pass

        return {
            "target": target,
            "in_scope": in_scope,
            "phase": state_info.get("phase", "DISCOVERY"),
            "mode": state_info.get("mode", "research"),
            "technologies": technologies,
            "endpoints": endpoints[:50],  # Limit cap
            "skills": skills[:20],
            "previous_findings": findings,
            "failed_approaches": failed_approaches,
        }
