"""
NYX Worker Node Heartbeat Monitor
Manages worker node liveness signals and status health updates.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List
from nyx.worker.node import WorkerNode


class WorkerHeartbeat:
    """Monitors worker node liveness and detects stale/offline nodes."""

    def __init__(self, timeout_seconds: int = 60):
        self.timeout_seconds = timeout_seconds

    def send_heartbeat(self, node: WorkerNode) -> Dict[str, Any]:
        """Record liveness signal for worker node."""
        node.last_seen = datetime.now().isoformat()
        if node.status == "OFFLINE":
            node.status = "ONLINE"
        return node.get_metadata()

    def check_health(self, node_metadata: Dict[str, Any]) -> str:
        """Check whether worker node has timed out."""
        last_seen_str = node_metadata.get("last_seen")
        if not last_seen_str:
            return "OFFLINE"

        try:
            ls_time = datetime.fromisoformat(last_seen_str)
            if datetime.now() - ls_time > timedelta(seconds=self.timeout_seconds):
                return "OFFLINE"
        except Exception:
            return "OFFLINE"

        return node_metadata.get("status", "ONLINE")
