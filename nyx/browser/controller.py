"""
NYX Browser Controller
Manages active browser instances, session creation, context lookup, and global event dispatching.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.browser.context import BrowserContext
from nyx.browser.events import BrowserEvents
from nyx.browser.session import BrowserSession
from nyx.browser.storage import BrowserStorage


class BrowserController:
    """Controller managing active browser sessions and context persistence."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.storage = BrowserStorage(base_dir=base_dir)
        self.events = BrowserEvents()
        self._active_sessions: Dict[str, BrowserSession] = {}

    def create_session(
        self,
        target: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        authentication_state: Optional[Dict[str, Any]] = None,
    ) -> BrowserSession:
        """Create a new managed browser session."""
        ctx = BrowserContext(
            target=target,
            cookies=cookies,
            headers=headers,
            authentication_state=authentication_state,
        )
        session = BrowserSession(context=ctx, events=self.events)
        self._active_sessions[ctx.session_id] = session
        self.storage.save_context(ctx)
        return session

    def get_session(self, session_id: str) -> Optional[BrowserSession]:
        """Get an active browser session instance."""
        if session_id in self._active_sessions:
            return self._active_sessions[session_id]

        # Attempt restore from storage
        ctx = self.storage.load_context(session_id)
        if ctx:
            session = BrowserSession(context=ctx, events=self.events)
            self._active_sessions[session_id] = session
            return session

        return None

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List active and stored browser sessions."""
        return self.storage.list_contexts()

    def close_session(self, session_id: str) -> bool:
        """Close and deactivate a browser session."""
        session = self.get_session(session_id)
        if session:
            session.close()
            if session_id in self._active_sessions:
                del self._active_sessions[session_id]
            return True
        return False
