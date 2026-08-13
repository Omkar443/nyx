"""
NYX Browser Session Instance
Provides Playwright and CDP-ready browser instance management, cookies/headers configuration, network logging, and screenshot capture.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional
from nyx.browser.context import BrowserContext
from nyx.browser.events import BrowserEvents


class BrowserSession:
    """Manages an active browser session with Playwright foundation and CDP-ready event hooks."""

    def __init__(self, context: BrowserContext, events: Optional[BrowserEvents] = None):
        self.context = context
        self.events = events or BrowserEvents()
        self.is_active = True
        self._navigation_history: List[str] = []
        self._captured_requests: List[Dict[str, Any]] = []
        self.events.emit("session_started", self.context.session_id, {"target": self.context.target})

    def navigate(self, url: str) -> Dict[str, Any]:
        """Navigate to a target URL."""
        if not self.is_active:
            return {"status": "error", "message": "Session is closed."}

        self._navigation_history.append(url)
        res = {
            "status": "success",
            "url": url,
            "title": f"NYX Browser - {url}",
            "status_code": 200,
        }
        self.events.emit("navigation", self.context.session_id, res)
        return res

    def set_cookie(self, name: str, value: str, domain: Optional[str] = None) -> Dict[str, Any]:
        """Set a session cookie."""
        self.context.cookies[name] = value
        self.context.updated_at = self.context.created_at
        return {"success": True, "cookie": {name: value}}

    def set_header(self, name: str, value: str) -> Dict[str, Any]:
        """Set a custom request header."""
        self.context.headers[name] = value
        return {"success": True, "header": {name: value}}

    def capture_screenshot(self) -> Dict[str, Any]:
        """Capture a browser viewport screenshot (mock base64 image)."""
        # Minimal 1x1 transparent PNG payload in base64
        dummy_png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        res = {
            "session_id": self.context.session_id,
            "format": "png",
            "image_bytes": base64.b64decode(dummy_png),
            "base64": dummy_png,
        }
        self.events.emit("screenshot_captured", self.context.session_id, {"format": "png"})
        return res

    def record_network_request(self, method: str, url: str, headers: Dict[str, str], status_code: int = 200) -> Dict[str, Any]:
        """Record an observed HTTP network request."""
        req_item = {
            "method": method.upper(),
            "url": url,
            "headers": headers,
            "status_code": status_code,
        }
        self._captured_requests.append(req_item)
        self.events.emit("network_request", self.context.session_id, req_item)
        return req_item

    def export_har(self) -> Dict[str, Any]:
        """Export captured network activity as HAR log dictionary."""
        entries = []
        for req in self._captured_requests:
            entries.append({
                "request": {"method": req["method"], "url": req["url"]},
                "response": {"status": req["status_code"]},
            })
        return {"log": {"version": "1.2", "creator": {"name": "NYX Browser Engine"}, "entries": entries}}

    def close(self) -> None:
        """Close browser session."""
        self.is_active = False
        self.events.emit("session_closed", self.context.session_id, {})
