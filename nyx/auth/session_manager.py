"""
NYX Session Manager & Token Lifecycle Tracking
Tracks active session tokens, detects expirations, and handles token restoration.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from nyx.auth.providers import AuthProviders
from nyx.auth.flows import AuthFlows


class SessionManager:
    """Manages active session token lifecycles and expiration monitoring."""

    def __init__(
        self,
        providers: Optional[AuthProviders] = None,
        flows: Optional[AuthFlows] = None,
    ):
        self.providers = providers or AuthProviders()
        self.flows = flows or AuthFlows()
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

    def register_session(
        self,
        session_id: str,
        target: str,
        token: str,
        token_type: str = "Bearer",
        ttl_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """Register an active authenticated session token."""
        expires_at = datetime.now() + timedelta(seconds=ttl_seconds)
        sess = {
            "session_id": session_id,
            "target": target,
            "token": token,
            "token_type": token_type,
            "created_at": datetime.now().isoformat(),
            "expires_at": expires_at.isoformat(),
            "expired": False,
        }
        self._active_sessions[session_id] = sess
        return sess

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        sess = self._active_sessions.get(session_id)
        if not sess:
            return None

        # Expiration check
        try:
            exp = datetime.fromisoformat(sess["expires_at"])
            if datetime.now() > exp:
                sess["expired"] = True
        except Exception:
            pass

        return sess

    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        out = {}
        for k, v in self._active_sessions.items():
            out[k] = self.get_session(k) or v
        return out
