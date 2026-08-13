"""
NYX Agent Reasoning Context Engine
Aggregates target scope, technology stack, attack surface, historical findings, and skill inventory.
"""
from __future__ import annotations

from typing import Any, Dict, List
from nyx.ai.context import ContextEngine


class AgentContextEngine:
    """Aggregates security intelligence context for autonomous agent decision making."""

    def __init__(self):
        self._inner_engine = ContextEngine()

    def get_agent_context(self, target: str) -> Dict[str, Any]:
        """Generate structured reasoning context dictionary."""
        raw_ctx = self._inner_engine.get_target_context(target)
        
        return {
            "target": target,
            "in_scope": raw_ctx.get("in_scope", True),
            "phase": raw_ctx.get("phase", "DISCOVERY"),
            "technologies": raw_ctx.get("technologies", []),
            "endpoints": raw_ctx.get("endpoints", []),
            "endpoints_count": raw_ctx.get("endpoints_count", 0),
            "skills_matched": raw_ctx.get("skills_matched", []),
            "previous_findings": raw_ctx.get("previous_findings", []),
            "failed_approaches": raw_ctx.get("failed_approaches", []),
            "recommended_tests": [
                f"Test authentication flows for {target}",
                f"Check authorization boundaries on harvested endpoints",
                f"Inspect parameters for IDOR / Injection vulnerabilities",
            ],
        }
