"""
NYX AI Provider Registry Module
"""
from __future__ import annotations

from typing import Dict, Type
from nyx.ai.base import AIProvider
from nyx.ai.providers.gemini import GeminiProvider
from nyx.ai.providers.claude import ClaudeProvider
from nyx.ai.providers.openai import OpenAIProvider
from nyx.ai.providers.local import LocalLLMProvider

_PROVIDERS: Dict[str, Type[AIProvider]] = {
    "gemini": GeminiProvider,
    "claude": ClaudeProvider,
    "openai": OpenAIProvider,
    "local": LocalLLMProvider,
}


def get_provider_class(name: str) -> Type[AIProvider]:
    """Retrieve provider class by name."""
    norm = (name or "gemini").lower()
    if norm not in _PROVIDERS:
        return GeminiProvider
    return _PROVIDERS[norm]


__all__ = [
    "AIProvider",
    "GeminiProvider",
    "ClaudeProvider",
    "OpenAIProvider",
    "LocalLLMProvider",
    "get_provider_class",
]
