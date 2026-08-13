"""
NYX Agent Distributed Scheduler
Schedules tasks to available specialized agents based on type, capability, and priority.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.agent.tasks import DistributedTaskQueue
from nyx.agent.manager.registry import AgentRegistry


class DistributedScheduler:
    """Scheduler matching queued security tasks to capable registered agents."""

    def __init__(self, registry: AgentRegistry, task_queue: DistributedTaskQueue):
        self.registry = registry
        self.task_queue = task_queue

    def schedule_next_task(self) -> Optional[Dict[str, Any]]:
        """Find the highest-priority pending task and assign it to an available agent."""
        pending_tasks = self.task_queue.list_tasks(status="QUEUED")
        if not pending_tasks:
            pending_tasks = self.task_queue.list_tasks(status="CREATED")

        if not pending_tasks:
            return None

        for task in pending_tasks:
            req_type = task.get("agent_type", "recon")
            target = task.get("target", "")

            # Look for matching active agent
            candidates = self.registry.list_agents(target=target, agent_type=req_type)
            if not candidates:
                candidates = self.registry.list_agents(agent_type=req_type)

            if candidates:
                chosen = candidates[0]
                agent_id = chosen.get("agent_id")
                task_id = task.get("task_id")

                self.task_queue.update_task_status(
                    task_id=task_id,
                    status="RUNNING",
                    assigned_agent_id=agent_id,
                )
                task["assigned_agent_id"] = agent_id
                task["status"] = "RUNNING"
                return task

        return None
