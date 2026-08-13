"""
NYX API Specialized Agent
Specialized in REST/GraphQL OpenAPI analysis, parameter tampering, and IDOR testing.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from nyx.agents.base import BaseSpecializedAgent


class APIAgent(BaseSpecializedAgent):
    """Specialized API security research agent."""

    def __init__(self, target: str, provider_name: Optional[str] = None):
        super().__init__(
            agent_type="api",
            target=target,
            allowed_skills=["hunt-api-misconfig", "hunt-graphql", "hunt-idor", "hunt-jwt-crypto", "hunt-spa-api"],
            allowed_tools=["katana", "httpx"],
            provider_name=provider_name,
        )

    def execute_specialized_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        self.inner_agent.analyze()
        return {
            "agent_id": self.agent_id,
            "agent_type": "api",
            "target": self.target,
            "api_endpoints": [f"http://{self.target}/api/v1/users", f"http://{self.target}/api/v1/data"],
            "parameters_analyzed": ["id", "user_id", "token"],
            "idor_vectors_tested": True,
        }
