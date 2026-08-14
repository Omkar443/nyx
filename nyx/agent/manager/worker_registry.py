"""
NYX Worker Node Registry Module
Tracks remote worker nodes, authentication tokens, status health, and capability profiles.
Persists worker registration state in .engagement/database/workers.json.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.infrastructure.filesystem import _get_eng_dir, atomic_write_json
from nyx.worker.node import WorkerNode
from nyx.worker.heartbeat import WorkerHeartbeat


class WorkerRegistry:
    """Registry managing remote worker nodes registered with NYX Controller."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir
        self._workers: Dict[str, WorkerNode] = {}
        self.heartbeat_monitor = WorkerHeartbeat()
        self._load_from_disk()

    def _get_storage_file(self) -> Path:
        d = _get_eng_dir(create=True, base_dir=self.base_dir)
        db_dir = d / "database"
        db_dir.mkdir(exist_ok=True)
        return db_dir / "workers.json"

    def _load_from_disk(self) -> None:
        wf = self._get_storage_file()
        if not wf.exists():
            return
        try:
            raw = json.loads(wf.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                for item in raw:
                    node = WorkerNode.from_dict(item)
                    self._workers[node.worker_id] = node
        except Exception:
            pass

    def _save_to_disk(self) -> None:
        wf = self._get_storage_file()
        data = [w.get_metadata() for w in self._workers.values()]
        atomic_write_json(wf, data)

    def register_worker(self, node: WorkerNode) -> str:
        """Register a worker node instance."""
        self._workers[node.worker_id] = node
        self._save_to_disk()
        return node.worker_id

    def remove_worker(self, worker_id: str) -> bool:
        """Remove a registered worker node."""
        if worker_id in self._workers:
            del self._workers[worker_id]
            self._save_to_disk()
            return True
        return False

    def get_worker(self, worker_id: str) -> Optional[WorkerNode]:
        """Look up a worker node by ID."""
        return self._workers.get(worker_id)

    def list_workers(self, status: Optional[str] = None, agent_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List registered worker nodes with health checks."""
        res = list(self._workers.values())
        output = []
        state_changed = False

        for w in res:
            meta = w.get_metadata()
            current_status = self.heartbeat_monitor.check_health(meta)
            if current_status != w.status:
                w.status = current_status
                state_changed = True
                meta["status"] = current_status
            output.append(meta)

        if state_changed:
            self._save_to_disk()

        if status:
            output = [w for w in output if w.get("status", "").lower() == status.lower()]
        if agent_type:
            output = [w for w in output if agent_type.lower() in [a.lower() for a in w.get("agents_supported", [])]]

        return output

    def clear(self) -> None:
        """Clear all registered workers."""
        self._workers.clear()
        self._save_to_disk()
