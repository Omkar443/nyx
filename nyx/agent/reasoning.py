"""
NYX Agent Reasoning Coordinator
Coordinates AI reasoning provider outputs with policy boundaries and security context.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from nyx.ai.manager import AIManager
from nyx.security.ai_policy import AIPolicyEngine


class ReasoningEngine:
    """Coordinates AI provider analysis with security policy checks."""

    def __init__(self, provider_name: Optional[str] = None):
        self.provider_name = (provider_name or "gemini").lower()
        self.ai_manager = AIManager(default_provider=self.provider_name)
        self.policy_engine = AIPolicyEngine()

    def analyze_target(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AI provider analysis on target security context."""
        ok, msg = self.policy_engine.check_action_permitted("passive_recon", target)
        
        prompt = f"Analyze security research surface for target '{target}'."
        analysis_ctx = context if isinstance(context, dict) else {"target": target}
        raw_ai = self.ai_manager.analyze(analysis_ctx, prompt=prompt)

        return {
            "target": target,
            "analysis": raw_ai.get("analysis", f"Analyzed attack surface for {target}"),
            "policy_status": "PERMITTED" if ok else "BLOCKED",
            "authorized": ok,
            "policy_reason": msg,
        }
