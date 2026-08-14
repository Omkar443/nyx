"""
NYX Base Specialized Agent Definition
Extends NYXAgent with agent type metadata, allowed skills, tools, and structured output schemas.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.agent.agent import NYXAgent


class BaseSpecializedAgent:
    """Base class for specialized autonomous research agents."""

    def __init__(
        self,
        agent_type: str,
        target: str,
        allowed_skills: Optional[List[str]] = None,
        allowed_tools: Optional[List[str]] = None,
        provider_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        agent_state: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        base_dir: Optional[Path] = None,
    ):
        self.agent_id = agent_id or f"AGT-{agent_type.upper()}-{uuid.uuid4().hex[:6].upper()}"
        self.agent_type = agent_type
        self.target = target
        self.base_dir = base_dir
        self.allowed_skills = allowed_skills or []
        self.allowed_tools = allowed_tools or []
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = updated_at or self.created_at
        self.inner_agent = NYXAgent(provider_name=provider_name)
        self.inner_agent.start_mission(target)
        if agent_state:
            try:
                self.inner_agent.state_machine.set_state(agent_state, force=True)
            except Exception:
                pass

    def get_info(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "target": self.target,
            "agent_state": self.inner_agent.state_machine.current_state,
            "allowed_skills": self.allowed_skills,
            "allowed_tools": self.allowed_tools,
            "pending_approvals_count": len(self.inner_agent.approval_system.get_pending_approvals()),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
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

    @classmethod
    def from_dict(cls, data: Dict[str, Any], provider_name: Optional[str] = None, base_dir: Optional[Path] = None) -> BaseSpecializedAgent:
        agent_type = data.get("agent_type", "recon").lower()
        target = data.get("target", "example.com")
        agent_id = data.get("agent_id")
        agent_state = data.get("agent_state")
        created_at = data.get("created_at")
        updated_at = data.get("updated_at")

        if agent_type == "web":
            from nyx.agents.web_agent import WebAgent
            ag = WebAgent(target=target, provider_name=provider_name)
        elif agent_type == "api":
            from nyx.agents.api_agent import APIAgent
            ag = APIAgent(target=target, provider_name=provider_name)
        elif agent_type == "technology":
            from nyx.agents.technology_agent import TechnologyAgent
            ag = TechnologyAgent(target=target, provider_name=provider_name)
        elif agent_type == "validation":
            from nyx.agents.validation_agent import ValidationAgent
            ag = ValidationAgent(target=target, provider_name=provider_name)
        elif agent_type == "reporting":
            from nyx.agents.reporting_agent import ReportingAgent
            ag = ReportingAgent(target=target, provider_name=provider_name)
        else:
            from nyx.agents.recon_agent import ReconAgent
            ag = ReconAgent(target=target, provider_name=provider_name)

        if agent_id:
            ag.agent_id = agent_id
        if created_at:
            ag.created_at = created_at
        if updated_at:
            ag.updated_at = updated_at
        if agent_state:
            try:
                ag.inner_agent.state_machine.set_state(agent_state, force=True)
            except Exception:
                pass
        ag.base_dir = base_dir
        return ag
