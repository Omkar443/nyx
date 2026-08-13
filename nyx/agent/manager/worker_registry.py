"""
NYX Worker Node Registry Module
Tracks remote worker nodes, authentication tokens, status health, and capability profiles.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.worker.node import WorkerNode
from nyx.worker.heartbeat import WorkerHeartbeat


class WorkerRegistry:
    """Registry managing remote worker nodes registered with NYX Controller."""

    def __init__(self):
        self._workers: Dict[str, WorkerNode] = {}
        self.heartbeat_monitor = WorkerHeartbeat()

    def register_worker(self, node: WorkerNode) -> str:
        """Register a worker node instance."""
        self._workers[node.worker_id] = node
        return node.worker_id

    def remove_worker(self, worker_id: str) -> bool:
        """Remove a registered worker node."""
        if worker_id in self._workers:
            del self._workers[worker_id]
            return True
        return False

    def get_worker(self, worker_id: str) -> Optional[WorkerNode]:
        """Look up a worker node by ID."""
        return self._workers.get(worker_id)

    def list_workers(self, status: Optional[str] = None, agent_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List registered worker nodes with health checks."""
        res = list(self._workers.values())
        output = []
        for w in res:
            meta = w.get_metadata()
            # Update health status via heartbeat monitor
            current_status = self.heartbeat_monitor.check_health(meta)
            meta["status"] = current_status
            output.append(meta)

        if status:
            output = [w for w in output if w.get("status", "").lower() == status.lower()]
        if agent_type:
            output = [w for w in output if agent_type.lower() in [a.lower() for a in w.get("agents_supported", [])]]

        return output

    def clear(self) -> None:
        """Clear all registered workers."""
        self._workers.clear()
