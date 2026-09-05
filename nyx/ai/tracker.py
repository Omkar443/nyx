"""
NYX Active Mission Tracker Singleton
Tracks real-time execution lifecycle and progress of autonomous security missions.
"""
from __future__ import annotations

import time
import threading
from typing import Any, Dict, Optional


class ActiveMissionTracker:
    """Thread-safe singleton tracking live autonomous mission execution state."""

    _instance: Optional[ActiveMissionTracker] = None
    _singleton_lock = threading.Lock()

    def __new__(cls) -> ActiveMissionTracker:
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._lock = threading.RLock()
        self.is_running: bool = False
        self.status: str = "idle"  # "idle" | "running" | "paused_for_approval" | "completed" | "error"
        self.target: Optional[str] = None
        self.provider_name: Optional[str] = None
        self.active_permitted: bool = False
        self.auto_approve: bool = False
        self.max_iterations: int = 15
        self.current_iteration: int = 1
        self.started_at: Optional[float] = None
        self.ended_at: Optional[float] = None
        self.last_progress: Optional[Dict[str, Any]] = None
        self.pending_approval: Optional[Dict[str, Any]] = None
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self._initialized = True

    def start(
        self,
        target: str,
        provider_name: Optional[str] = None,
        active_permitted: bool = False,
        max_iterations: int = 15,
        start_iteration: int = 1,
        auto_approve: bool = False,
    ) -> None:
        with self._lock:
            self.is_running = True
            self.status = "running"
            self.target = target
            self.provider_name = provider_name
            self.active_permitted = active_permitted
            self.auto_approve = auto_approve
            self.max_iterations = max_iterations
            self.current_iteration = start_iteration
            if start_iteration <= 1 or not self.started_at:
                self.started_at = time.time()
            self.ended_at = None
            self.pending_approval = None
            self.error = None
            self.last_progress = {
                "state": "initializing",
                "message": "Initializing mission context...",
                "target": target,
                "iteration": start_iteration,
                "max_iterations": max_iterations,
                "provider": provider_name,
                "auto_approved": auto_approve,
                "active_permitted": active_permitted,
            }

    def update_progress(self, progress_data: Dict[str, Any]) -> None:
        with self._lock:
            self.last_progress = dict(progress_data)
            if "iteration" in progress_data and progress_data["iteration"]:
                self.current_iteration = int(progress_data["iteration"])
            if "max_iterations" in progress_data and progress_data["max_iterations"]:
                self.max_iterations = int(progress_data["max_iterations"])
            if "provider" in progress_data and progress_data["provider"]:
                self.provider_name = progress_data["provider"]
            if "auto_approved" in progress_data and progress_data["auto_approved"]:
                self.auto_approve = True

            state = progress_data.get("state")
            if state in ("reasoning", "executing"):
                self.is_running = True
                self.status = "running"
            elif state == "paused":
                self.is_running = False
                self.status = "paused_for_approval"
                self.pending_approval = {
                    "step": progress_data.get("pending_step"),
                    "action_id": progress_data.get("action_id"),
                    "step_name": progress_data.get("step_name"),
                    "tool": progress_data.get("tool"),
                    "upcoming_pipeline": progress_data.get("upcoming_pipeline", []),
                    "remaining_destructive_count": progress_data.get("remaining_destructive_count", 0),
                    "current_step_index": progress_data.get("current_step_index", 1),
                    "total_planned_steps": progress_data.get("total_planned_steps", 1),
                }
            elif state == "completed":
                self.is_running = False
                self.status = "completed"
                self.ended_at = time.time()

    def pause(self, pending_data: Dict[str, Any]) -> None:
        with self._lock:
            self.is_running = False
            self.status = "paused_for_approval"
            self.pending_approval = dict(pending_data)

    def complete(self, result: Dict[str, Any]) -> None:
        with self._lock:
            self.is_running = False
            self.status = "completed"
            self.ended_at = time.time()
            self.result = result

    def fail(self, error_msg: str, details: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            self.is_running = False
            self.status = "error"
            self.ended_at = time.time()
            self.error = error_msg
            self.result = details

    def abort(self, reason: str = "System shutdown requested", details: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            self.is_running = False
            self.status = "aborted"
            self.ended_at = time.time()
            self.error = reason
            self.result = details
            if self.last_progress:
                self.last_progress["state"] = "aborted"
                self.last_progress["message"] = reason

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            if self.started_at:
                if self.is_running or self.status == "paused_for_approval":
                    elapsed = max(0, int(now - self.started_at))
                elif self.ended_at:
                    elapsed = max(0, int(self.ended_at - self.started_at))
                else:
                    elapsed = max(0, int(now - self.started_at))
            else:
                elapsed = 0

            return {
                "is_running": self.is_running,
                "status": self.status,
                "target": self.target,
                "provider_name": self.provider_name,
                "active_permitted": self.active_permitted,
                "auto_approve": self.auto_approve,
                "max_iterations": self.max_iterations,
                "current_iteration": self.current_iteration,
                "started_at": self.started_at,
                "elapsed_seconds": elapsed,
                "last_progress": self.last_progress,
                "pending_approval": self.pending_approval,
                "result": self.result,
                "error": self.error,
            }

    def reset(self) -> None:
        with self._lock:
            self.is_running = False
            self.status = "idle"
            self.target = None
            self.provider_name = None
            self.active_permitted = False
            self.auto_approve = False
            self.max_iterations = 15
            self.current_iteration = 1
            self.started_at = None
            self.ended_at = None
            self.last_progress = None
            self.pending_approval = None
            self.result = None
            self.error = None


active_mission_tracker = ActiveMissionTracker()
