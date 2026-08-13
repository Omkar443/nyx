"""
NYX Worker Security Module
Enforces worker node token verification, identity signatures, and scope validation.
"""
from __future__ import annotations

import hmac
import hashlib
from typing import Any, Dict, Tuple
from nyx.security.authorization import check_authorization, is_hostname_in_scope


class WorkerSecurity:
    """Security validator for worker node registration and task execution."""

    def __init__(self, secret_key: str = "NYX_WORKER_SECRET_KEY"):
        self.secret_key = secret_key.encode("utf-8")

    def generate_worker_token(self, worker_id: str, hostname: str) -> str:
        """Generate a signed HMAC authentication token for a worker node."""
        msg = f"{worker_id}:{hostname}".encode("utf-8")
        return hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

    def verify_worker_token(self, worker_id: str, hostname: str, token: str) -> bool:
        """Verify worker authentication token signature."""
        expected = self.generate_worker_token(worker_id, hostname)
        return hmac.compare_digest(expected, token)

    def validate_remote_execution(self, target: str) -> Tuple[bool, str]:
        """Verify target domain is authorized and within engagement scope."""
        auth_ok, auth_err = check_authorization()
        if not auth_ok:
            return False, f"[SECURITY BLOCKED] Worker execution unauthorized: {auth_err}"

        if not is_hostname_in_scope(target):
            return False, f"[SCOPE BLOCKED] Target '{target}' is outside engagement scope."

        return True, "Target verified for remote execution."
