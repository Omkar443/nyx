"""
NYX AI Provider Base Abstraction Interface
Defines standard provider interface for AI systems (Gemini, NYX AI, OpenAI, Local LLMs).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class AIProvider(ABC):
    """Abstract base class for all AI provider integrations."""

    provider_name: str = "base"

    @abstractmethod
    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        """Generate raw text response from prompt."""
        pass

    @abstractmethod
    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None) -> Dict[str, Any]:
        """Analyze security context and return structured analysis dict."""
        pass

    @abstractmethod
    def decide(self, context: Dict[str, Any], options: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Make a security action decision based on context and available options."""
        pass

    def get_info(self) -> Dict[str, Any]:
        """Return metadata info about provider."""
        return {
            "name": self.provider_name,
            "type": self.__class__.__name__,
            "status": "ready",
        }
