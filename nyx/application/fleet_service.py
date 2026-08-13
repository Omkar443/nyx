"""
NYX Fleet Application Service
Service facade exposing multi-agent fleet operations, specialized agent creation, task queue management, and fleet status.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.application.base import BaseService, ServiceResult
from nyx.agent.manager.controller import AgentController


class FleetService(BaseService):
    """Service facade for multi-agent distributed research platform."""

    def __init__(self, provider_name: Optional[str] = None):
        super().__init__()
        self.controller = AgentController(provider_name=provider_name)

    def create_agent(self, type: str, target: str) -> ServiceResult:
        res = self.controller.create_agent(type=type, target=target)
        return self.ok(data=res, message=f"Created specialized agent '{res.get('agent_id')}' of type '{type}' for '{target}'.")

    def list_agents(self, target: Optional[str] = None, agent_type: Optional[str] = None) -> ServiceResult:
        agents = self.controller.list_agents(target=target, agent_type=agent_type)
        return self.ok(data={"count": len(agents), "agents": agents}, message=f"Retrieved {len(agents)} active agents.")

    def stop_agent(self, agent_id: str) -> ServiceResult:
        ok = self.controller.stop_agent(agent_id)
        if not ok:
            return self.fail(message=f"Agent '{agent_id}' not found.", error_code="AGENT_NOT_FOUND")
        return self.ok(data={"agent_id": agent_id, "stopped": True}, message=f"Stopped agent '{agent_id}'.")

    def create_task(
        self,
        task_type: str,
        target: str,
        agent_type: str = "recon",
        priority: int = 5,
        params: Optional[Dict[str, Any]] = None,
    ) -> ServiceResult:
        task = self.controller.task_queue.create_task(
            task_type=task_type,
            target=target,
            agent_type=agent_type,
            priority=priority,
            params=params,
        )
        return self.ok(data=task, message=f"Created task '{task.get('task_id')}' for agent type '{agent_type}'.")

    def list_tasks(self, status: Optional[str] = None) -> ServiceResult:
        tasks = self.controller.task_queue.list_tasks(status=status)
        return self.ok(data={"count": len(tasks), "tasks": tasks}, message=f"Retrieved {len(tasks)} tasks.")

    def multi_start_mission(self, targets: List[str]) -> ServiceResult:
        created = []
        for t in targets:
            r_agent = self.controller.create_agent(type="recon", target=t)
            w_agent = self.controller.create_agent(type="web", target=t)
            created.extend([r_agent, w_agent])
        return self.ok(data={"created_count": len(created), "agents": created}, message=f"Started multi-agent mission across {len(targets)} targets.")

    def get_fleet_status(self) -> ServiceResult:
        status = self.controller.get_fleet_status()
        return self.ok(data=status, message="Retrieved fleet status.")
