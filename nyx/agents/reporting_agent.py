"""
NYX Reporting Specialized Agent
Specialized in generating platform submission reports (Bugcrowd, HackerOne, Intigriti).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
from nyx.agents.base import BaseSpecializedAgent


class ReportingAgent(BaseSpecializedAgent):
    """Specialized security report writing agent."""

    def __init__(
        self,
        target: str,
        provider_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        agent_state: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        base_dir: Optional[Path] = None,
    ):
        super().__init__(
            agent_type="reporting",
            target=target,
            allowed_skills=["report-writing", "bugcrowd-reporting", "redteam-report-template"],
            allowed_tools=[],
            provider_name=provider_name,
            agent_id=agent_id,
            agent_state=agent_state,
            created_at=created_at,
            updated_at=updated_at,
            base_dir=base_dir,
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
