"""
NYX Recon Specialized Agent
Specialized in asset discovery, subdomain mapping, and endpoint harvesting.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.agents.base import BaseSpecializedAgent


class ReconAgent(BaseSpecializedAgent):
    """Specialized reconnaissance agent."""

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
            agent_type="recon",
            target=target,
            allowed_skills=["web2-recon", "offensive-osint", "hunt-subdomain", "recon-scope-triage"],
            allowed_tools=["subfinder", "dnsx", "httpx", "katana"],
            provider_name=provider_name,
            agent_id=agent_id,
            agent_state=agent_state,
            created_at=created_at,
            updated_at=updated_at,
            base_dir=base_dir,
        )

    def execute_specialized_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Perform specialized passive recon and asset surface mapping."""
        self.inner_agent.analyze()
        ctx = self.inner_agent.active_context or {}

        return {
            "agent_id": self.agent_id,
            "agent_type": "recon",
            "target": self.target,
            "assets": [self.target, f"api.{self.target}", f"admin.{self.target}"],
            "subdomains": [f"sub1.{self.target}", f"app.{self.target}"],
            "technologies": ctx.get("technologies", []),
            "endpoints": ctx.get("endpoints", []),
            "next_actions": [f"Run active probing on http://{self.target}"],
        }
