"""
NYX Worker Task Executor
Executes specialized tasks through specialized agents.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
from nyx.agents.api_agent import APIAgent
from nyx.agents.recon_agent import ReconAgent
from nyx.agents.reporting_agent import ReportingAgent
from nyx.agents.technology_agent import TechnologyAgent
from nyx.agents.validation_agent import ValidationAgent
from nyx.agents.web_agent import WebAgent
from nyx.agent.manager.registry import AgentRegistry
from nyx.worker.security import WorkerSecurity


class WorkerExecutor:
    """Task execution module responsible for executing individual tasks."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir
        self.sec_checker = WorkerSecurity(base_dir=base_dir)

    def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a claimed task through its assigned or specialized agent."""
        task_id = task.get("task_id", "")
        agent_type = task.get("agent_type", "recon").lower()
        target = task.get("target", "example.com")
        assigned_agent_id = task.get("assigned_agent_id")

        # 1. Enforce authorization & safety layer check before active execution
        sec_ok, sec_err = self.sec_checker.validate_remote_execution(target, base_dir=self.base_dir)
        if not sec_ok:
            return {
                "task_id": task_id,
                "status": "FAILED",
                "error": sec_err,
                "security_blocked": True,
            }

        # 2. Re-use assigned agent from registry if available
        ag = None
        if assigned_agent_id:
            reg = AgentRegistry(base_dir=self.base_dir)
            ag = reg.get_agent(assigned_agent_id)

        if not ag:
            if agent_type == "web":
                ag = WebAgent(target=target, agent_id=assigned_agent_id, base_dir=self.base_dir)
            elif agent_type == "api":
                ag = APIAgent(target=target, agent_id=assigned_agent_id, base_dir=self.base_dir)
            elif agent_type == "technology":
                ag = TechnologyAgent(target=target, agent_id=assigned_agent_id, base_dir=self.base_dir)
            elif agent_type == "validation":
                ag = ValidationAgent(target=target, agent_id=assigned_agent_id, base_dir=self.base_dir)
            elif agent_type == "reporting":
                ag = ReportingAgent(target=target, agent_id=assigned_agent_id, base_dir=self.base_dir)
            else:
                ag = ReconAgent(target=target, agent_id=assigned_agent_id, base_dir=self.base_dir)

        ag.base_dir = self.base_dir
        res = ag.execute_specialized_task(task)
        return {
            "task_id": task_id,
            "status": "COMPLETED",
            "agent_id": ag.agent_id,
            "result": res,
        }
