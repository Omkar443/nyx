"""
NYX Distributed Authentication Foundation
Manages worker node identity verification and signed message authentication.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple
from nyx.worker.security import WorkerSecurity


class DistributedAuthentication:
    """Handles worker identity verification and mutual authentication checks."""

    def __init__(self):
        self.security = WorkerSecurity()

    def authenticate_worker(self, worker_id: str, hostname: str, token: str) -> Tuple[bool, str]:
        """Verify worker identity and HMAC token signature."""
        if not worker_id or not token:
            return False, "Missing worker ID or token."

        ok = self.security.verify_worker_token(worker_id, hostname, token)
        if not ok:
            return False, f"Invalid token signature for worker '{worker_id}'."

        return True, "Worker node authenticated successfully."
