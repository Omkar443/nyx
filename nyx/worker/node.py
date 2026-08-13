"""
NYX Worker Node Framework
Represents a remote execution node registered with the central NYX Controller.
"""
from __future__ import annotations

import platform
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from nyx.worker.security import WorkerSecurity

WORKER_VALID_STATES: List[str] = ["ONLINE", "BUSY", "OFFLINE", "ERROR"]


class WorkerNode:
    """Remote worker node capable of executing assigned agent workloads."""

    def __init__(
        self,
        hostname: Optional[str] = None,
        agents_supported: Optional[List[str]] = None,
        worker_id: Optional[str] = None,
    ):
        self.worker_id = worker_id or f"WRK-{uuid.uuid4().hex[:8].upper()}"
        self.hostname = hostname or platform.node() or "localhost"
        self.platform = f"{platform.system()} {platform.release()}"
        self.agents_supported = agents_supported or ["recon", "web", "api", "technology", "validation", "reporting"]
        self.status = "ONLINE"
        self.last_seen = datetime.now().isoformat()

        sec = WorkerSecurity()
        self.auth_token = sec.generate_worker_token(self.worker_id, self.hostname)

    def update_status(self, status: str) -> bool:
        """Update worker operational status."""
        st = status.upper()
        if st in WORKER_VALID_STATES:
            self.status = st
            self.last_seen = datetime.now().isoformat()
            return True
        return False

    def get_metadata(self) -> Dict[str, Any]:
        """Get structured metadata dictionary for worker registration."""
        return {
            "worker_id": self.worker_id,
            "hostname": self.hostname,
            "platform": self.platform,
            "agents_supported": self.agents_supported,
            "status": self.status,
            "last_seen": self.last_seen,
            "auth_token": self.auth_token,
        }
