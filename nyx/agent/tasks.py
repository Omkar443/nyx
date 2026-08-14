"""
NYX Distributed Task Queue
Manages priority task scheduling, remote worker assignments, retry policies, and task recovery.
Persists task queue state in .engagement/database/tasks.json.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.infrastructure.filesystem import _get_eng_dir, atomic_write_json

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

    def __init__(self, max_retries: int = 3, base_dir: Optional[Path] = None):
        self.base_dir = base_dir
        self.max_retries = max_retries
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._load_from_disk()

    def _get_storage_file(self) -> Path:
        d = _get_eng_dir(create=True, base_dir=self.base_dir)
        db_dir = d / "database"
        db_dir.mkdir(exist_ok=True)
        return db_dir / "tasks.json"

    def _load_from_disk(self) -> None:
        tf = self._get_storage_file()
        if not tf.exists():
            return
        try:
            raw = json.loads(tf.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                for item in raw:
                    if isinstance(item, dict) and "task_id" in item:
                        self._tasks[item["task_id"]] = item
        except Exception:
            pass

    def _save_to_disk(self) -> None:
        tf = self._get_storage_file()
        data = list(self._tasks.values())
        atomic_write_json(tf, data)

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
        self._load_from_disk()
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
            "claimed_by": None,
            "claimed_at": None,
            "result_location": None,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "result": None,
            "error": None,
            "execution_history": [],
        }
        self._tasks[task_id] = task
        self._save_to_disk()
        return task

    def claim_task(self, task_id: str, claimed_by: str) -> bool:
        """Atomically claim an eligible task for execution by a runtime instance."""
        self._load_from_disk()
        if task_id not in self._tasks:
            return False
        t = self._tasks[task_id]
        if t.get("status") in ("COMPLETED", "FAILED"):
            return False
        current_claim = t.get("claimed_by")
        if current_claim and current_claim != claimed_by:
            return False

        t["claimed_by"] = claimed_by
        t["claimed_at"] = datetime.now().isoformat()
        t["updated_at"] = datetime.now().isoformat()
        self._save_to_disk()
        return True

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
        self._load_from_disk()
        st = status.upper()
        if st not in TASK_VALID_STATES:
            return False, f"Invalid task state '{st}'."
        if task_id not in self._tasks:
            return False, f"Task '{task_id}' not found."

        t = self._tasks[task_id]
        t["status"] = st
        t["updated_at"] = datetime.now().isoformat()

        if st == "COMPLETED":
            # Successful final execution -> COMPLETED and no active failure error
            t["error"] = error if error is not None else None
            t.setdefault("execution_history", []).append({
                "timestamp": datetime.now().isoformat(),
                "attempt": t.get("retry_count", 0) + 1,
                "status": "COMPLETED",
                "result": result,
            })
        else:
            if error is not None:
                t["error"] = error

        if result is not None:
            t["result"] = result
        if assigned_agent_id is not None:
            t["assigned_agent_id"] = assigned_agent_id
        if assigned_worker_id is not None:
            t["assigned_worker_id"] = assigned_worker_id
        if execution_mode is not None:
            t["execution_mode"] = execution_mode.upper()

        self._save_to_disk()
        return True, f"Task '{task_id}' state updated to '{st}'."

    def fail_task(self, task_id: str, reason: str = "") -> tuple[bool, str]:
        """Fail task or queue for retry if under max_retries limit."""
        self._load_from_disk()
        if task_id not in self._tasks:
            return False, f"Task '{task_id}' not found."

        t = self._tasks[task_id]
        attempt = t.get("retry_count", 0) + 1
        t.setdefault("execution_history", []).append({
            "timestamp": datetime.now().isoformat(),
            "attempt": attempt,
            "status": "FAILED",
            "error": reason,
        })
        t["retry_count"] = attempt

        if t["retry_count"] <= t["max_retries"]:
            t["status"] = "QUEUED"
            t["assigned_worker_id"] = None
            t["assigned_agent_id"] = None
            t["claimed_by"] = None
            t["claimed_at"] = None
            t["error"] = f"Retry {t['retry_count']}/{t['max_retries']}: {reason}"
            t["updated_at"] = datetime.now().isoformat()
            self._save_to_disk()
            return True, f"Task '{task_id}' failed, queued for retry {t['retry_count']}."
        else:
            t["status"] = "FAILED"
            t["error"] = f"Max retries exceeded ({t['retry_count']}/{t['max_retries']}): {reason}"
            t["updated_at"] = datetime.now().isoformat()
            self._save_to_disk()
            return True, f"Task '{task_id}' permanently marked FAILED."

    def recover_stale_tasks(self, timeout_seconds: int = 300) -> int:
        """Recover running tasks that timed out without completion."""
        self._load_from_disk()
        recovered = 0
        now = datetime.now()
        for t in list(self._tasks.values()):
            if t["status"] == "RUNNING":
                try:
                    up_time = datetime.fromisoformat(t["updated_at"])
                    if now - up_time > timedelta(seconds=timeout_seconds):
                        self.fail_task(t["task_id"], reason="Execution timed out on worker.")
                        recovered += 1
                except Exception:
                    pass
        if recovered > 0:
            self._save_to_disk()
        return recovered

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        self._load_from_disk()
        return self._tasks.get(task_id)

    def list_tasks(
        self,
        status: Optional[str] = None,
        agent_type: Optional[str] = None,
        execution_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tasks sorted by priority (descending)."""
        self._load_from_disk()
        res = list(self._tasks.values())
        if status:
            res = [t for t in res if t.get("status") == status.upper()]
        if agent_type:
            res = [t for t in res if t.get("agent_type") == agent_type]
        if execution_mode:
            res = [t for t in res if t.get("execution_mode") == execution_mode.upper()]

        return sorted(res, key=lambda x: x.get("priority", 5), reverse=True)

    def clear(self) -> None:
        """Clear all registered tasks."""
        self._tasks.clear()
        self._save_to_disk()
