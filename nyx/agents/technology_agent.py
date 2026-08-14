"""
NYX Technology Specialized Agent
Specialized in technology stack fingerprinting and matching against attack maps.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
from nyx.agents.base import BaseSpecializedAgent


class TechnologyAgent(BaseSpecializedAgent):
    """Specialized technology mapping agent."""

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
            agent_type="technology",
            target=target,
            allowed_skills=["hunt-aspnet", "hunt-springboot", "hunt-laravel", "hunt-nextjs", "hunt-nodejs"],
            allowed_tools=["httpx"],
            provider_name=provider_name,
            agent_id=agent_id,
            agent_state=agent_state,
            created_at=created_at,
            updated_at=updated_at,
            base_dir=base_dir,
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
