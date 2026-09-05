"""
NYX Research Opportunity Engine
Analyzes surface changes and maps them to recommended skills from NYX knowledge library.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from nyx.research.priority import PriorityRanker


class OpportunityEngine:
    """Generates research recommendations matched to existing NYX skills."""

    SKILL_MAPPINGS = {
        "graphql": ["hunt-graphql", "hunt-api-misconfig", "hunt-idor"],
        "api": ["hunt-api-misconfig", "hunt-jwt-crypto", "hunt-cors"],
        "auth": ["hunt-ato", "hunt-mfa-bypass", "hunt-session", "hunt-oauth"],
        "admin": ["hunt-auth-bypass", "hunt-idor", "hunt-aspnet"],
        "upload": ["hunt-file-upload", "hunt-xxe", "hunt-lfi"],
    }

    def __init__(self):
        self._opportunities: List[Dict[str, Any]] = []

    def analyze_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Map a change event to security research opportunities."""
        desc = event.get("description", "").lower()
        target = event.get("target", "example.com")
        recommended_skills = ["web2-recon", "offensive-osint"]

        for keyword, skills in self.SKILL_MAPPINGS.items():
            if keyword in desc:
                for s in skills:
                    if s not in recommended_skills:
                        recommended_skills.append(s)

        opp = {
            "opportunity_id": f"OPP-{uuid.uuid4().hex[:8].upper()}",
            "target": target,
            "title": f"Research Opportunity: {event.get('event_type')}",
            "description": event.get("description", ""),
            "severity": event.get("severity", "MEDIUM"),
            "recommended_skills": recommended_skills,
            "status": "OPEN",
        }
        self._opportunities.append(opp)
        return opp

    def list_opportunities(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        opps = list(self._opportunities)
        if target:
            from nyx.security.authorization import parse_target_tuple
            from nyx.ai.context import _matches_target_endpoint
            _, t_host, _ = parse_target_tuple(target)
            filtered = []
            for o in opps:
                o_target = o.get("target", "")
                _, o_host, _ = parse_target_tuple(o_target)
                if (t_host and o_host == t_host) or _matches_target_endpoint(o_target, target):
                    filtered.append(o)
            opps = filtered
        return PriorityRanker.rank_opportunities(opps)
