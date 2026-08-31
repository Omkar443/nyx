"""
NYX AI Provider Registry Module
"""
from __future__ import annotations

from typing import Dict, Type
from nyx.ai.base import AIProvider
from nyx.ai.providers.gemini import GeminiProvider
from nyx.ai.providers.grok import GrokProvider
from nyx.ai.providers.groq import GroqProvider
from nyx.ai.providers.claude import ClaudeProvider
from nyx.ai.providers.openai import OpenAIProvider
from nyx.ai.providers.local import LocalLLMProvider
from nyx.ai.providers.local_llama import LocalLlamaProvider

_PROVIDERS: Dict[str, Type[AIProvider]] = {
    "gemini": GeminiProvider,
    "grok": GrokProvider,
    "groq": GroqProvider,
    "claude": ClaudeProvider,
    "openai": OpenAIProvider,
    "local": LocalLlamaProvider,
    "llama": LocalLlamaProvider,
    "deepseek": LocalLlamaProvider,
    "offline": LocalLLMProvider,
}


def get_provider_class(name: str) -> Type[AIProvider]:
    """Retrieve provider class by name."""
    norm = (name or "groq").lower()
    if norm not in _PROVIDERS:
        return _PROVIDERS.get("groq", LocalLlamaProvider)
    return _PROVIDERS[norm]


__all__ = [
    "AIProvider",
    "GeminiProvider",
    "GrokProvider",
    "GroqProvider",
    "ClaudeProvider",
    "OpenAIProvider",
    "LocalLLMProvider",
    "LocalLlamaProvider",
    "get_provider_class",
]
