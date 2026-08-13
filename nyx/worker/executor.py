"""
NYX Worker Remote Task Executor
Executes approved security agent workloads inside isolated worker sandboxes.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from nyx.worker.security import WorkerSecurity
from nyx.agents import ReconAgent, WebAgent, APIAgent, TechnologyAgent, ValidationAgent, ReportingAgent


class WorkerExecutor:
    """Executes remote agent tasks on worker nodes."""

    def __init__(self):
        self.security = WorkerSecurity()

    def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute assigned task using matching specialized agent."""
        target = task.get("target", "example.com")
        agent_type = task.get("agent_type", "recon").lower()
        task_id = task.get("task_id", "TSK-UNKNOWN")

        # 1. Scope & Auth check
        sec_ok, sec_err = self.security.validate_remote_execution(target)
        if not sec_ok:
            return {
                "task_id": task_id,
                "status": "FAILED",
                "error": sec_err,
                "security_blocked": True,
            }

        # 2. Instantiate agent & execute
        if agent_type == "web":
            ag = WebAgent(target=target)
        elif agent_type == "api":
            ag = APIAgent(target=target)
        elif agent_type == "technology":
            ag = TechnologyAgent(target=target)
        elif agent_type == "validation":
            ag = ValidationAgent(target=target)
        elif agent_type == "reporting":
            ag = ReportingAgent(target=target)
        else:
            ag = ReconAgent(target=target)

        res = ag.execute_specialized_task(task)
        return {
            "task_id": task_id,
            "status": "COMPLETED",
            "agent_id": ag.agent_id,
            "result": res,
        }
