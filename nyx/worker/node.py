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
        platform_info: Optional[str] = None,
        status: Optional[str] = None,
        last_seen: Optional[str] = None,
        auth_token: Optional[str] = None,
        created_at: Optional[str] = None,
        name: Optional[str] = None,
    ):
        self.worker_id = worker_id or f"WRK-{uuid.uuid4().hex[:8].upper()}"
        self.hostname = hostname or platform.node() or "localhost"
        self.name = name or self.hostname
        self.platform = platform_info or f"{platform.system()} {platform.release()}"
        self.agents_supported = agents_supported or ["recon", "web", "api", "technology", "validation", "reporting"]
        self.status = status or "ONLINE"
        self.created_at = created_at or datetime.now().isoformat()
        self.last_seen = last_seen or self.created_at

        if auth_token:
            self.auth_token = auth_token
        else:
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
            "name": self.name,
            "hostname": self.hostname,
            "platform": self.platform,
            "agents_supported": self.agents_supported,
            "status": self.status,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "auth_token": self.auth_token,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkerNode:
        return cls(
            worker_id=data.get("worker_id"),
            hostname=data.get("hostname"),
            name=data.get("name"),
            agents_supported=data.get("agents_supported"),
            platform_info=data.get("platform"),
            status=data.get("status"),
            last_seen=data.get("last_seen"),
            auth_token=data.get("auth_token"),
            created_at=data.get("created_at"),
        )
