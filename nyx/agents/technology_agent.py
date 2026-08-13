"""
NYX Technology Specialized Agent
Specialized in technology stack fingerprinting and matching against attack maps.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from nyx.agents.base import BaseSpecializedAgent


class TechnologyAgent(BaseSpecializedAgent):
    """Specialized technology mapping agent."""

    def __init__(self, target: str, provider_name: Optional[str] = None):
        super().__init__(
            agent_type="technology",
            target=target,
            allowed_skills=["hunt-aspnet", "hunt-springboot", "hunt-laravel", "hunt-nextjs", "hunt-nodejs"],
            allowed_tools=["httpx"],
            provider_name=provider_name,
        )

    def execute_specialized_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        self.inner_agent.analyze()
        return {
            "agent_id": self.agent_id,
            "agent_type": "technology",
            "target": self.target,
            "detected_stack": ["ASP.NET", "Microsoft-IIS", "React"],
            "matched_mappings": ["skills/mappings/technologies/aspnet.yaml"],
        }
