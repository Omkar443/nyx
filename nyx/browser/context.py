"""
NYX Browser Context Data Model
Stores browser context state, target domain, session ID, cookies, headers, and authentication permissions.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


class BrowserContext:
    """Represents a browser execution context state."""

    def __init__(
        self,
        target: str,
        session_id: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        authentication_state: Optional[Dict[str, Any]] = None,
        permissions: Optional[List[str]] = None,
    ):
        self.session_id = session_id or f"SESS-{uuid.uuid4().hex[:8].upper()}"
        self.target = target
        self.cookies = cookies or {}
        self.headers = headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NYX-Security-Engine/1.0"}
        self.authentication_state = authentication_state or {"authenticated": False, "user": None, "token": None}
        self.permissions = permissions or ["geolocation", "notifications"]
        self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "cookies": self.cookies,
            "headers": self.headers,
            "authentication_state": self.authentication_state,
            "permissions": self.permissions,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BrowserContext:
        return cls(
            target=data.get("target", "example.com"),
            session_id=data.get("session_id"),
            cookies=data.get("cookies"),
            headers=data.get("headers"),
            authentication_state=data.get("authentication_state"),
            permissions=data.get("permissions"),
        )
