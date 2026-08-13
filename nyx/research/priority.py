"""
NYX Priority Ranker
Ranks research opportunities based on attack surface impact and severity.
"""
from __future__ import annotations

from typing import Any, Dict, List


class PriorityRanker:
    """Ranks research opportunities by impact score."""

    SEVERITY_SCORES = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 1,
    }

    @classmethod
    def rank_opportunities(cls, opportunities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort research opportunities by priority score descending."""
        for opp in opportunities:
            sev = opp.get("severity", "MEDIUM").upper()
            score = cls.SEVERITY_SCORES.get(sev, 5)
            if "graphql" in opp.get("description", "").lower():
                score += 2
            if "admin" in opp.get("description", "").lower() or "auth" in opp.get("description", "").lower():
                score += 3
            opp["priority_score"] = score

        return sorted(opportunities, key=lambda x: x.get("priority_score", 0), reverse=True)
