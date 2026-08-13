"""
NYX Runtime JavaScript Observer
Monitors client-side JavaScript execution, script endpoints, inline handlers, and console logs.
"""
from __future__ import annotations

from typing import Any, Dict, List


class JSObserver:
    """Monitors JavaScript assets and client-side execution events."""

    def __init__(self):
        self._scripts: List[str] = []
        self._endpoints: List[str] = []
        self._console_logs: List[Dict[str, Any]] = []

    def record_script(self, src: str) -> None:
        """Record a loaded script source URL."""
        if src not in self._scripts:
            self._scripts.append(src)

    def record_discovered_endpoint(self, endpoint: str) -> None:
        """Record an endpoint string discovered inside client-side JS bundles."""
        if endpoint not in self._endpoints:
            self._endpoints.append(endpoint)

    def record_console_log(self, level: str, message: str) -> None:
        """Record a browser console event."""
        self._console_logs.append({"level": level.lower(), "message": message})

    def get_summary(self) -> Dict[str, Any]:
        return {
            "scripts_count": len(self._scripts),
            "scripts": list(self._scripts),
            "discovered_endpoints": list(self._endpoints),
            "console_logs_count": len(self._console_logs),
            "console_logs": list(self._console_logs),
        }
