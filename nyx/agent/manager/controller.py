"""
NYX Multi-Agent Controller
Central orchestrator managing specialized agents, task assignments, worker nodes, message bus events, and fleet monitoring.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from nyx.agent.bus import AgentMessageBus
from nyx.agent.tasks import DistributedTaskQueue
from nyx.agent.manager.registry import AgentRegistry
from nyx.agent.manager.scheduler import DistributedScheduler
from nyx.agent.manager.worker_registry import WorkerRegistry
from nyx.agent.manager.worker_scheduler import WorkerScheduler
from nyx.worker.node import WorkerNode
from nyx.agents import (
    BaseSpecializedAgent,
    ReconAgent,
    WebAgent,
    APIAgent,
    TechnologyAgent,
    ValidationAgent,
    ReportingAgent,
    DynamicAgent,
)


class AgentController:
    """Central controller orchestrating specialized agent fleet, worker nodes, and task execution."""

    def __init__(self, provider_name: Optional[str] = None, base_dir: Optional[Path] = None):
        self.provider_name = provider_name or os.environ.get("NYX_AI_PROVIDER") or os.environ.get("AI_PROVIDER")
        self.base_dir = base_dir
        self.bus = AgentMessageBus()
        self.registry = AgentRegistry(base_dir=base_dir)
        self.worker_registry = WorkerRegistry(base_dir=base_dir)
        self.task_queue = DistributedTaskQueue(base_dir=base_dir)
        self.scheduler = DistributedScheduler(self.registry, self.task_queue)
        self.worker_scheduler = WorkerScheduler(self.registry, self.worker_registry, self.task_queue)

    def create_agent(self, type: str, target: str) -> Dict[str, Any]:
        """Create and register a specialized research agent instance."""
        t_norm = type.lower().strip()
        agent: BaseSpecializedAgent

        if t_norm == "recon":
            agent = ReconAgent(target=target, provider_name=self.provider_name)
        elif t_norm == "web":
            agent = WebAgent(target=target, provider_name=self.provider_name)
        elif t_norm == "api":
            agent = APIAgent(target=target, provider_name=self.provider_name)
        elif t_norm == "technology":
            agent = TechnologyAgent(target=target, provider_name=self.provider_name)
        elif t_norm == "validation":
            agent = ValidationAgent(target=target, provider_name=self.provider_name)
        elif t_norm == "reporting":
            agent = ReportingAgent(target=target, provider_name=self.provider_name)
        elif t_norm == "dynamic":
            agent = DynamicAgent(target=target, provider_name=self.provider_name)
        else:
            agent = ReconAgent(target=target, provider_name=self.provider_name)

        agent_id = self.registry.register_agent(agent)
        info = agent.get_info()

        self.bus.publish(
            sender="CONTROLLER",
            receiver=agent_id,
            event_type="agent_started",
            payload=info,
        )

        return info

    def stop_agent(self, agent_id: str) -> bool:
        """Stop and unregister an agent instance."""
        agent = self.registry.get_agent(agent_id)
        if not agent:
            return False

        info = agent.get_info()
        self.registry.unregister_agent(agent_id)

        self.bus.publish(
            sender="CONTROLLER",
            receiver=agent_id,
            event_type="agent_stopped",
            payload={"agent_id": agent_id, "info": info},
        )
        return True

    def register_worker(self, hostname: str, agents_supported: Optional[List[str]] = None) -> Dict[str, Any]:
        """Register a remote worker node."""
        node = WorkerNode(hostname=hostname, agents_supported=agents_supported)
        w_id = self.worker_registry.register_worker(node)
        meta = node.get_metadata()

        self.bus.publish(
            sender="CONTROLLER",
            receiver=w_id,
            event_type="worker_registered",
            payload=meta,
        )
        return meta

    def remove_worker(self, worker_id: str) -> bool:
        """Remove a remote worker node."""
        ok = self.worker_registry.remove_worker(worker_id)
        if ok:
            self.bus.publish(
                sender="CONTROLLER",
                receiver=worker_id,
                event_type="worker_removed",
                payload={"worker_id": worker_id},
            )
        return ok

    def list_workers(self, status: Optional[str] = None, agent_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List registered remote worker nodes."""
        return self.worker_registry.list_workers(status=status, agent_type=agent_type)

    def list_agents(self, target: Optional[str] = None, agent_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List active agents in fleet."""
        return self.registry.list_agents(target=target, agent_type=agent_type)

    def get_fleet_status(self) -> Dict[str, Any]:
        """Get aggregated fleet status, task queue metrics, worker nodes, and active agents."""
        agents = self.registry.list_agents()
        workers = self.worker_registry.list_workers()
        tasks = self.task_queue.list_tasks()
        history = self.bus.get_history()

        pending_approvals = sum(a.get("pending_approvals_count", 0) for a in agents)

        return {
            "total_agents": len(agents),
            "total_workers": len(workers),
            "total_tasks": len(tasks),
            "pending_approvals_count": pending_approvals,
            "agents": agents,
            "workers": workers,
            "tasks": tasks,
            "recent_events_count": len(history),
        }
