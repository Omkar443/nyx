"""
NYX Runtime Request Logger
Logs HTTP requests/responses, parameters, and query strings during dynamic browser observation.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class RequestLogger:
    """Logs and categorizes HTTP traffic captured during dynamic browser execution."""

    def __init__(self):
        self._requests: List[Dict[str, Any]] = []

    def log_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict[str, Any]] = None,
        status_code: int = 200,
    ) -> Dict[str, Any]:
        """Record an observed HTTP request."""
        item = {
            "method": method.upper(),
            "url": url,
            "headers": headers,
            "params": params or {},
            "status_code": status_code,
        }
        self._requests.append(item)
        return item

    def get_requests(self) -> List[Dict[str, Any]]:
        """Return all logged requests."""
        return list(self._requests)
