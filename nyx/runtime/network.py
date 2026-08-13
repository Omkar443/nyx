"""
NYX Runtime Network Observer
Observes API calls, GraphQL operations, and REST endpoints captured during browser navigation.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.runtime.requests import RequestLogger


class NetworkObserver:
    """Monitors and categorizes network traffic into API, GraphQL, and parameter structures."""

    def __init__(self, logger: Optional[RequestLogger] = None):
        self.logger = logger or RequestLogger()
        self._apis: List[Dict[str, Any]] = []
        self._graphql_ops: List[Dict[str, Any]] = []

    def observe(self, method: str, url: str, headers: Dict[str, str], params: Optional[Dict[str, Any]] = None, status_code: int = 200) -> Dict[str, Any]:
        """Observe and log a network event."""
        req = self.logger.log_request(method, url, headers, params, status_code)
        
        # Categorize API & GraphQL calls
        if "/api/" in url or "/v1/" in url or "/v2/" in url or "/v3/" in url or "graphql" in url:
            api_item = {"endpoint": url, "method": method.upper(), "type": "graphql" if "graphql" in url else "rest"}
            self._apis.append(api_item)
            if "graphql" in url:
                self._graphql_ops.append(api_item)

        return req

    def get_apis(self) -> List[Dict[str, Any]]:
        return list(self._apis)

    def get_graphql_operations(self) -> List[Dict[str, Any]]:
        return list(self._graphql_ops)
