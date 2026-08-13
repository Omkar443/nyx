"""
NYX Browser Event Hooks & Listener Module
Captures browser lifecycle events including navigation, requests, responses, console errors, and DOM mutations.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


class BrowserEvents:
    """Event dispatcher for browser automation lifecycle events."""

    def __init__(self):
        self._listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._event_log: List[Dict[str, Any]] = []

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        if callback not in self._listeners:
            self._listeners.append(callback)

    def emit(self, event_name: str, session_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        evt = {
            "event_name": event_name,
            "session_id": session_id,
            "data": data,
            "timestamp": datetime.now().isoformat(),
        }
        self._event_log.append(evt)

        for listener in self._listeners:
            try:
                listener(evt)
            except Exception:
                pass

        return evt

    def get_events(self, session_id: Optional[str] = None, event_name: Optional[str] = None) -> List[Dict[str, Any]]:
        res = self._event_log
        if session_id:
            res = [e for e in res if e.get("session_id") == session_id]
        if event_name:
            res = [e for e in res if e.get("event_name") == event_name]
        return res
