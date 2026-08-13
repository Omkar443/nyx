"""
NYX Agent Registry Module
Tracks active specialized security research agents, state, target assignment, and capability filtering.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.agents.base import BaseSpecializedAgent


class AgentRegistry:
    """Central registry tracking active specialized agents across targets."""

    def __init__(self):
        self._agents: Dict[str, BaseSpecializedAgent] = {}

    def register_agent(self, agent: BaseSpecializedAgent) -> str:
        """Register a new specialized agent instance."""
        self._agents[agent.agent_id] = agent
        return agent.agent_id

    def unregister_agent(self, agent_id: str) -> bool:
        """Unregister an agent instance."""
        if agent_id in self._agents:
            del self._agents[agent_id]
            return True
        return False

    def get_agent(self, agent_id: str) -> Optional[BaseSpecializedAgent]:
        """Look up an agent instance by ID."""
        return self._agents.get(agent_id)

    def list_agents(
        self,
        target: Optional[str] = None,
        agent_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List registered agents with optional target, type, and status filtering."""
        res = list(self._agents.values())

        if target:
            res = [a for a in res if a.target == target]
        if agent_type:
            res = [a for a in res if a.agent_type.lower() == agent_type.lower()]
        if status:
            res = [a for a in res if a.inner_agent.state_machine.current_state.lower() == status.lower()]

        return [a.get_info() for a in res]

    def clear(self) -> None:
        """Clear all registered agents."""
        self._agents.clear()
