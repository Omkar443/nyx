"""
NYX Worker Security Module
Enforces worker node token verification, identity signatures, and scope validation.
"""
from __future__ import annotations

import hmac
import hashlib
from pathlib import Path
from typing import Any, Dict, Tuple, Optional
from nyx.security.authorization import check_authorization, is_hostname_in_scope


class WorkerSecurity:
    """Security validator for worker node registration and task execution."""

    def __init__(self, secret_key: str = "NYX_WORKER_SECRET_KEY", base_dir: Optional[Path] = None):
        self.secret_key = secret_key.encode("utf-8")
        self.base_dir = base_dir

    def generate_worker_token(self, worker_id: str, hostname: str) -> str:
        """Generate a signed HMAC authentication token for a worker node."""
        msg = f"{worker_id}:{hostname}".encode("utf-8")
        return hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

    def verify_worker_token(self, worker_id: str, hostname: str, token: str) -> bool:
        """Verify worker authentication token signature."""
        expected = self.generate_worker_token(worker_id, hostname)
        return hmac.compare_digest(expected, token)

    def validate_remote_execution(self, target: str, base_dir: Optional[Path] = None) -> Tuple[bool, str]:
        """Verify target domain is authorized and within engagement scope."""
        b_dir = base_dir or self.base_dir
        auth_ok, auth_err = check_authorization(base_dir=b_dir)
        if not auth_ok:
            return False, f"[SECURITY BLOCKED] Worker execution unauthorized: {auth_err}"

        if not is_hostname_in_scope(target, base_dir=b_dir):
            return False, f"[SCOPE BLOCKED] Target '{target}' is outside engagement scope."

        return True, "Target verified for remote execution."
