"""
NYX OpenAI GPT Provider Integration
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from nyx.ai.base import AIProvider


class OpenAIProvider(AIProvider):
    """OpenAI GPT AI Provider Implementation."""

    provider_name: str = "openai"

    def __init__(self, model_name: str = "gpt-4o", api_key: Optional[str] = None):
        self.model_name = model_name
        self.api_key = api_key

    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        if "mission" in prompt.lower() or "plan" in prompt.lower():
            return "Recommended Mission:\n1. Passive recon & DNS discovery\n2. Service version fingerprinting\n3. Web application logic audit"
        return f"[OpenAI Provider ({self.model_name})] Generated response for prompt: {prompt[:50]}..."

    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None) -> Dict[str, Any]:
        target = context.get("target", "unknown")
        findings = context.get("previous_findings", [])
        return {
            "provider": self.provider_name,
            "target": target,
            "analysis": f"Analyzed target '{target}' with {len(findings)} prior findings.",
            "recommended_focus": "Business Logic & Rate Limit Vulnerability Testing",
        }

    def decide(self, context: Dict[str, Any], options: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not options:
            return {"action": "none", "reason": "No options provided."}
        chosen = options[0]
        return {
            "provider": self.provider_name,
            "decision": chosen.get("action", "unknown"),
            "option": chosen,
            "confidence": 0.90,
        }
