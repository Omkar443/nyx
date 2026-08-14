"""
NYX Agent Registry Module
Tracks active specialized security research agents, state, target assignment, and capability filtering.
Persists registered agent state in .engagement/database/agents.json.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.infrastructure.filesystem import _get_eng_dir, atomic_write_json
from nyx.agents.base import BaseSpecializedAgent


class AgentRegistry:
    """Central registry tracking active specialized agents across targets."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir
        self._agents: Dict[str, BaseSpecializedAgent] = {}
        self._load_from_disk()

    def _get_storage_file(self) -> Path:
        d = _get_eng_dir(create=True, base_dir=self.base_dir)
        db_dir = d / "database"
        db_dir.mkdir(exist_ok=True)
        return db_dir / "agents.json"

    def _load_from_disk(self) -> None:
        af = self._get_storage_file()
        if not af.exists():
            return
        try:
            raw = json.loads(af.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                for item in raw:
                    agent = BaseSpecializedAgent.from_dict(item, base_dir=self.base_dir)
                    self._agents[agent.agent_id] = agent
            self._reconcile_stale_agent_states()
        except Exception:
            pass

    def _reconcile_stale_agent_states(self) -> None:
        """Ensure agents without active RUNNING tasks return to IDLE state."""
        from nyx.agent.tasks import DistributedTaskQueue
        tq = DistributedTaskQueue(base_dir=self.base_dir)
        running_tasks = tq.list_tasks(status="RUNNING")
        active_agent_ids = {t.get("assigned_agent_id") for t in running_tasks if t.get("assigned_agent_id")}

        changed = False
        for agent_id, agent in self._agents.items():
            curr_state = agent.inner_agent.state_machine.current_state.upper()
            if curr_state in ("ANALYZING", "RUNNING") and agent_id not in active_agent_ids:
                try:
                    agent.inner_agent.state_machine.set_state("IDLE", force=True)
                    changed = True
                except Exception:
                    pass
        if changed:
            af = self._get_storage_file()
            data = [a.get_info() for a in self._agents.values()]
            atomic_write_json(af, data)

    def _save_to_disk(self) -> None:
        af = self._get_storage_file()
        data = [a.get_info() for a in self._agents.values()]
        atomic_write_json(af, data)

    def register_agent(self, agent: BaseSpecializedAgent) -> str:
        """Register a new specialized agent instance."""
        self._load_from_disk()
        self._agents[agent.agent_id] = agent
        self._save_to_disk()
        return agent.agent_id

    def unregister_agent(self, agent_id: str) -> bool:
        """Unregister an agent instance."""
        self._load_from_disk()
        if agent_id in self._agents:
            del self._agents[agent_id]
            self._save_to_disk()
            return True
        return False

    def get_agent(self, agent_id: str) -> Optional[BaseSpecializedAgent]:
        """Look up an agent instance by ID."""
        self._load_from_disk()
        return self._agents.get(agent_id)

    def list_agents(
        self,
        target: Optional[str] = None,
        agent_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List registered agents with optional target, type, and status filtering."""
        self._load_from_disk()
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
        self._save_to_disk()
