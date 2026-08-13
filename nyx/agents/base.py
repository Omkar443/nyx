"""
NYX Base Specialized Agent Definition
Extends NYXAgent with agent type metadata, allowed skills, tools, and structured output schemas.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from nyx.agent.agent import NYXAgent


class BaseSpecializedAgent:
    """Base class for specialized autonomous research agents."""

    def __init__(
        self,
        agent_type: str,
        target: str,
        allowed_skills: List[str],
        allowed_tools: List[str],
        provider_name: Optional[str] = None,
    ):
        self.agent_id = f"AGT-{agent_type.upper()}-{uuid.uuid4().hex[:6].upper()}"
        self.agent_type = agent_type
        self.target = target
        self.allowed_skills = allowed_skills
        self.allowed_tools = allowed_tools
        self.inner_agent = NYXAgent(provider_name=provider_name)
        self.inner_agent.start_mission(target)

    def get_info(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "target": self.target,
            "agent_state": self.inner_agent.state_machine.current_state,
            "allowed_skills": self.allowed_skills,
            "allowed_tools": self.allowed_tools,
            "pending_approvals_count": len(self.inner_agent.approval_system.get_pending_approvals()),
        }

    def execute_specialized_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Base execution stub to be overridden by specialized subclasses."""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "target": self.target,
            "status": "completed",
            "results": {},
        }
