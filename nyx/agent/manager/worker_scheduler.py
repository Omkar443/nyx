"""
NYX Worker Task Scheduler
Decides whether to execute tasks using local agent instances or dispatch to remote worker nodes.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from nyx.agent.manager.registry import AgentRegistry
from nyx.agent.manager.worker_registry import WorkerRegistry
from nyx.agent.tasks import DistributedTaskQueue


class WorkerScheduler:
    """Dispatches tasks locally or to remote worker nodes based on availability."""

    def __init__(
        self,
        agent_registry: AgentRegistry,
        worker_registry: WorkerRegistry,
        task_queue: DistributedTaskQueue,
    ):
        self.agent_registry = agent_registry
        self.worker_registry = worker_registry
        self.task_queue = task_queue

    def dispatch_task(self, task_id: str) -> Dict[str, Any]:
        """Dispatch task to local agent or remote worker node."""
        task = self.task_queue.get_task(task_id)
        if not task:
            return {"success": False, "error": f"Task '{task_id}' not found."}

        req_agent_type = task.get("agent_type", "recon")
        target = task.get("target", "")

        # Check local agent availability first
        local_agents = self.agent_registry.list_agents(target=target, agent_type=req_agent_type)
        if local_agents:
            chosen = local_agents[0]
            self.task_queue.update_task_status(
                task_id=task_id,
                status="RUNNING",
                assigned_agent_id=chosen["agent_id"],
                execution_mode="LOCAL",
            )
            return {
                "success": True,
                "execution_mode": "LOCAL",
                "assigned_agent_id": chosen["agent_id"],
                "task": self.task_queue.get_task(task_id),
            }

        # Look for online remote worker nodes supporting requested agent type
        remote_workers = self.worker_registry.list_workers(status="ONLINE", agent_type=req_agent_type)
        if remote_workers:
            chosen_worker = remote_workers[0]
            w_id = chosen_worker["worker_id"]
            self.task_queue.update_task_status(
                task_id=task_id,
                status="RUNNING",
                assigned_worker_id=w_id,
                execution_mode="REMOTE",
            )
            return {
                "success": True,
                "execution_mode": "REMOTE",
                "assigned_worker_id": w_id,
                "task": self.task_queue.get_task(task_id),
            }

        return {
            "success": False,
            "error": f"No available local agent or remote worker for agent type '{req_agent_type}'.",
        }
