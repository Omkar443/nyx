"""
NYX AI Manager
Manages AI provider configuration, registration, active provider switching, and reasoning dispatch.
"""
from __future__ import annotations

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


class AIManager:
    """Central AI provider manager and dispatcher."""

    def __init__(self, default_provider: str = "gemini"):
        self._instances: Dict[str, AIProvider] = {
            "gemini": GeminiProvider(),
            "grok": GrokProvider(),
            "groq": GroqProvider(),
            "claude": ClaudeProvider(),
            "openai": OpenAIProvider(),
            "local": LocalLLMProvider(),
        }
        self.active_provider_name: str = default_provider.lower()

    def get_provider(self, name: Optional[str] = None) -> AIProvider:
        """Get an AI provider instance by name or return the active provider."""
        target_name = (name or self.active_provider_name).lower()
        if target_name not in self._instances:
            cls = get_provider_class(target_name)
            self._instances[target_name] = cls()
        return self._instances[target_name]

    def set_active_provider(self, name: str) -> bool:
        """Switch active AI provider."""
        norm = name.lower()
        if norm in self._instances or norm in ("gemini", "grok", "groq", "claude", "openai", "local"):
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
        """Perform security context analysis using active or specified provider."""
        prov = self.get_provider(provider_name)
        return prov.analyze(context, prompt=prompt)

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
