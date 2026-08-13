"""
NYX Distributed Task Queue
Manages priority task scheduling, remote worker assignments, retry policies, and task recovery.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

TASK_VALID_STATES: List[str] = [
    "CREATED",
    "QUEUED",
    "RUNNING",
    "WAITING_APPROVAL",
    "COMPLETED",
    "FAILED",
]


class DistributedTaskQueue:
    """Priority task queue supporting remote worker dispatch, task recovery, and retries."""

    def __init__(self, max_retries: int = 3):
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self.max_retries = max_retries

    def create_task(
        self,
        task_type: str,
        target: str,
        agent_type: str = "recon",
        priority: int = 5,
        params: Optional[Dict[str, Any]] = None,
        dependencies: Optional[List[str]] = None,
        execution_mode: str = "LOCAL",
        execution_timeout: int = 300,
    ) -> Dict[str, Any]:
        """Create and register a new security research task."""
        task_id = f"TSK-{uuid.uuid4().hex[:8].upper()}"
        task = {
            "task_id": task_id,
            "task_type": task_type,
            "target": target,
            "agent_type": agent_type,
            "priority": priority,
            "params": params or {},
            "dependencies": dependencies or [],
            "status": "CREATED",
            "execution_mode": execution_mode.upper(),
            "assigned_agent_id": None,
            "assigned_worker_id": None,
            "execution_timeout": execution_timeout,
            "retry_count": 0,
            "max_retries": self.max_retries,
            "result_location": None,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "result": None,
            "error": None,
        }
        self._tasks[task_id] = task
        return task

    def update_task_status(
        self,
        task_id: str,
        status: str,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        assigned_agent_id: Optional[str] = None,
        assigned_worker_id: Optional[str] = None,
        execution_mode: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Update task execution status."""
        st = status.upper()
        if st not in TASK_VALID_STATES:
            return False, f"Invalid task state '{st}'."
        if task_id not in self._tasks:
            return False, f"Task '{task_id}' not found."

        t = self._tasks[task_id]
        t["status"] = st
        t["updated_at"] = datetime.now().isoformat()
        if result is not None:
            t["result"] = result
        if error is not None:
            t["error"] = error
        if assigned_agent_id is not None:
            t["assigned_agent_id"] = assigned_agent_id
        if assigned_worker_id is not None:
            t["assigned_worker_id"] = assigned_worker_id
        if execution_mode is not None:
            t["execution_mode"] = execution_mode.upper()

        return True, f"Task '{task_id}' state updated to '{st}'."

    def fail_task(self, task_id: str, reason: str = "") -> tuple[bool, str]:
        """Fail task or queue for retry if under max_retries limit."""
        if task_id not in self._tasks:
            return False, f"Task '{task_id}' not found."

        t = self._tasks[task_id]
        t["retry_count"] += 1

        if t["retry_count"] <= t["max_retries"]:
            t["status"] = "QUEUED"
            t["assigned_worker_id"] = None
            t["assigned_agent_id"] = None
            t["error"] = f"Retry {t['retry_count']}/{t['max_retries']}: {reason}"
            t["updated_at"] = datetime.now().isoformat()
            return True, f"Task '{task_id}' failed, queued for retry {t['retry_count']}."
        else:
            t["status"] = "FAILED"
            t["error"] = f"Max retries exceeded: {reason}"
            t["updated_at"] = datetime.now().isoformat()
            return True, f"Task '{task_id}' permanently marked FAILED."

    def recover_stale_tasks(self, timeout_seconds: int = 300) -> int:
        """Recover running tasks that timed out without completion."""
        recovered = 0
        now = datetime.now()
        for t in self._tasks.values():
            if t["status"] == "RUNNING":
                try:
                    up_time = datetime.fromisoformat(t["updated_at"])
                    if now - up_time > timedelta(seconds=timeout_seconds):
                        self.fail_task(t["task_id"], reason="Execution timed out on worker.")
                        recovered += 1
                except Exception:
                    pass
        return recovered

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        return self._tasks.get(task_id)

    def list_tasks(
        self,
        status: Optional[str] = None,
        agent_type: Optional[str] = None,
        execution_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tasks sorted by priority (descending)."""
        res = list(self._tasks.values())
        if status:
            res = [t for t in res if t.get("status") == status.upper()]
        if agent_type:
            res = [t for t in res if t.get("agent_type") == agent_type]
        if execution_mode:
            res = [t for t in res if t.get("execution_mode") == execution_mode.upper()]

        return sorted(res, key=lambda x: x.get("priority", 5), reverse=True)
