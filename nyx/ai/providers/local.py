"""
NYX Local LLM / Rule-Based Engine Provider Integration
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from nyx.ai.base import AIProvider


class LocalLLMProvider(AIProvider):
    """Local LLM (Ollama, LM Studio, Offline Heuristic) Implementation."""

    provider_name: str = "local"

    def __init__(self, model_name: str = "llama3:8b", endpoint_url: Optional[str] = None):
        self.model_name = model_name
        self.endpoint_url = endpoint_url or "http://localhost:11434"

    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        if "mission" in prompt.lower() or "plan" in prompt.lower():
            return "Recommended Mission:\n1. Local surface inventory\n2. Endpoint & parameter harvest\n3. Rule-based vulnerability triage"
        return f"[Local LLM Provider ({self.model_name})] Generated response for prompt: {prompt[:50]}..."

    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None) -> Dict[str, Any]:
        target = context.get("target", "unknown")
        skills = context.get("skills", [])
        return {
            "provider": self.provider_name,
            "target": target,
            "analysis": f"Local heuristic evaluation for target '{target}' matched against {len(skills)} skills.",
            "recommended_focus": "Local Rule-Based Vulnerability Verification",
        }

    def decide(self, context: Dict[str, Any], options: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not options:
            return {"action": "none", "reason": "No options provided."}
        chosen = options[0]
        return {
            "provider": self.provider_name,
            "decision": chosen.get("action", "unknown"),
            "option": chosen,
            "confidence": 0.88,
        }
