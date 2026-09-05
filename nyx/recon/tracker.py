"""
NYX Active Recon Tracker Singleton
Tracks real-time execution lifecycle and progress of surface reconnaissance jobs.
"""
from __future__ import annotations

import time
import threading
from typing import Any, Dict, Optional


class ActiveReconTracker:
    """Thread-safe singleton tracking live reconnaissance execution state."""

    _instance: Optional[ActiveReconTracker] = None
    _singleton_lock = threading.Lock()

    def __new__(cls) -> ActiveReconTracker:
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
        self.status: str = "idle"  # "idle" | "running" | "completed" | "error"
        self.target: Optional[str] = None
        self.current_phase: Optional[str] = None  # "subdomain_enum" | "dns_resolution" | "http_probing" | "content_discovery" | "syncing"
        self.phase_message: Optional[str] = None
        self.started_at: Optional[float] = None
        self.ended_at: Optional[float] = None
        self.progress: Dict[str, Any] = {}
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self._initialized = True

    def start(
        self,
        target: str,
        initial_phase: str = "subdomain_enum",
        message: str = "Starting reconnaissance...",
    ) -> None:
        with self._lock:
            self.is_running = True
            self.status = "running"
            self.target = target
            self.current_phase = initial_phase
            self.phase_message = message
            self.started_at = time.time()
            self.ended_at = None
            self.progress = {}
            self.result = None
            self.error = None

    def update_phase(self, phase: str, message: str, **kwargs: Any) -> None:
        with self._lock:
            self.current_phase = phase
            self.phase_message = message
            if kwargs:
                self.progress.update(kwargs)

    def complete(self, result: Dict[str, Any]) -> None:
        with self._lock:
            self.is_running = False
            self.status = "completed"
            self.ended_at = time.time()
            self.phase_message = "Reconnaissance completed"
            self.result = result

    def fail(self, error: str) -> None:
        with self._lock:
            self.is_running = False
            self.status = "error"
            self.ended_at = time.time()
            self.error = error
            self.phase_message = f"Recon failed: {error}"

    def reset(self) -> None:
        with self._lock:
            self.is_running = False
            self.status = "idle"
            self.target = None
            self.current_phase = None
            self.phase_message = None
            self.started_at = None
            self.ended_at = None
            self.progress = {}
            self.result = None
            self.error = None

    def get_status(self, target: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            # Check target isolation if target is specified
            if target and self.target:
                from nyx.security.authorization import parse_target_tuple
                from nyx.ai.context import _matches_target_endpoint

                _, q_host, _ = parse_target_tuple(target)
                _, t_host, _ = parse_target_tuple(self.target)

                matches = (
                    (q_host and t_host == q_host)
                    or _matches_target_endpoint(self.target, target)
                    or _matches_target_endpoint(target, self.target)
                )
                if not matches:
                    return {
                        "is_running": False,
                        "status": "idle",
                        "target": target,
                        "current_phase": None,
                        "phase_message": None,
                        "started_at": None,
                        "ended_at": None,
                        "elapsed_seconds": 0.0,
                        "progress": {},
                        "result": None,
                        "error": None,
                    }

            elapsed = 0.0
            if self.started_at:
                end_time = self.ended_at or time.time()
                elapsed = max(0.0, round(end_time - self.started_at, 1))

            return {
                "is_running": self.is_running,
                "status": self.status,
                "target": self.target,
                "current_phase": self.current_phase,
                "phase_message": self.phase_message,
                "started_at": self.started_at,
                "ended_at": self.ended_at,
                "elapsed_seconds": elapsed,
                "progress": dict(self.progress),
                "result": self.result,
                "error": self.error,
            }


active_recon_tracker = ActiveReconTracker()