"""
NYX AI Manager
Manages AI provider configuration, registration, active provider switching, and reasoning dispatch.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from nyx.ai.base import AIProvider
from nyx.ai.providers import (
    GeminiProvider,
    GrokProvider,
    GroqProvider,
    ClaudeProvider,
    OpenAIProvider,
    LocalLLMProvider,
    get_provider_class,
)


try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except Exception:
    pass


def detect_default_provider() -> str:
    """
    Auto-detect the first provider with a configured, valid API key from environment / .env.
    Checks providers in order: Groq, OpenAI, Claude, Grok, Gemini, Local.
    Never defaults blindly to Gemini if Gemini is not configured.
    """
    explicit = os.environ.get("NYX_AI_PROVIDER") or os.environ.get("AI_PROVIDER")
    if explicit:
        return explicit.lower().strip()

    # Auto-detect first provider with configured API key
    if os.environ.get("GROQ_API_KEY"):
        return "groq"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY"):
        return "claude"
    if os.environ.get("XAI_API_KEY") or os.environ.get("GROK_API_KEY"):
        return "grok"
    if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
        return "gemini"
    if os.environ.get("LOCAL_LLM_URL") or os.environ.get("OLLAMA_HOST"):
        return "local"

    # Default fallback
    return "groq"


class AIManager:
    """Central AI provider manager and dispatcher."""

    def __init__(self, default_provider: Optional[str] = None):
        self._instances: Dict[str, AIProvider] = {}
        chosen = default_provider or detect_default_provider()
        self.active_provider_name: str = chosen.lower()

    def get_provider(self, name: Optional[str] = None) -> AIProvider:
        """Get an AI provider instance by name or return the active provider."""
        target_name = (name or self.active_provider_name or detect_default_provider()).lower()
        if target_name not in self._instances:
            cls = get_provider_class(target_name)
            self._instances[target_name] = cls()
        return self._instances[target_name]

    def set_active_provider(self, name: str) -> bool:
        """Switch active AI provider."""
        norm = name.lower()
        if norm in ("gemini", "grok", "groq", "claude", "openai", "local"):
            self.active_provider_name = norm
            # Ensure instantiated
            self.get_provider(norm)
            return True
        return False

    def list_providers(self) -> List[Dict[str, Any]]:
        """List registered AI providers and their status."""
        providers = []
        for name in ["gemini", "grok", "groq", "claude", "openai", "local"]:
            inst = self.get_provider(name)
            info = inst.get_info()
            info["is_active"] = (name == self.active_provider_name)
            providers.append(info)
        return providers

    def generate(self, prompt: str, provider_name: Optional[str] = None, options: Optional[Dict[str, Any]] = None) -> str:
        """Generate text from active or specified provider."""
        prov = self.get_provider(provider_name)
        return prov.generate(prompt, options=options)

    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None, provider_name: Optional[str] = None) -> Dict[str, Any]:
        """Perform security context analysis using active or specified provider with strict fail-safe validation."""
        prov = self.get_provider(provider_name)
        target = context.get("target", "unknown")
        try:
            res = prov.analyze(context, prompt=prompt)
            if isinstance(res, dict):
                focus = res.get("recommended_focus") or res.get("focus") or res.get("decision")
                analysis_text = res.get("analysis") or res.get("reasoning")
                if (focus or "selected_index" in res) and analysis_text and isinstance(analysis_text, str):
                    return res
        except Exception as ex:
            return {
                "provider": prov.provider_name,
                "target": target,
                "recommended_focus": "AI analysis unavailable — using deterministic methodology",
                "analysis": f"AI provider execution error: {str(ex)}",
            }

        return {
            "provider": prov.provider_name,
            "target": target,
            "recommended_focus": "AI analysis unavailable — using deterministic methodology",
            "analysis": "AI response was empty or malformed — using deterministic methodology",
        }

    def decide(self, context: Dict[str, Any], options: List[Dict[str, Any]], provider_name: Optional[str] = None) -> Dict[str, Any]:
        """Make a security action decision using active or specified provider."""
        prov = self.get_provider(provider_name)
        return prov.decide(context, options=options)

    def test_provider(self, name: Optional[str] = None) -> Dict[str, Any]:
        """Run health check test for specified or active AI provider."""
        prov = self.get_provider(name)
        if hasattr(prov, "test_connection"):
            return prov.test_connection()
        info = prov.get_info()
        return {
            "provider": prov.provider_name,
            "success": info.get("status") == "ready",
            "status": info.get("status", "unknown"),
            "model": info.get("model", "default"),
            "message": f"Provider '{prov.provider_name}' status: {info.get('status')}",
        }
