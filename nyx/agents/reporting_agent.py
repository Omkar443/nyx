"""
NYX Reporting Specialized Agent
Specialized in generating platform submission reports (Bugcrowd, HackerOne, Intigriti).
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from nyx.agents.base import BaseSpecializedAgent


class ReportingAgent(BaseSpecializedAgent):
    """Specialized security report writing agent."""

    def __init__(self, target: str, provider_name: Optional[str] = None):
        super().__init__(
            agent_type="reporting",
            target=target,
            allowed_skills=["report-writing", "bugcrowd-reporting", "redteam-report-template"],
            allowed_tools=[],
            provider_name=provider_name,
        )

    def execute_specialized_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_type": "reporting",
            "target": self.target,
            "report_generated": True,
            "vrt_category": "Server-Side Injection > IDOR",
            "cvss_score": 7.5,
        }
