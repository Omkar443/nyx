"""
NYX Tool Adapter Base Interface
Abstract base class defining contract for security tool execution & output parsing adapters.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ToolAdapter(ABC):
    """Abstract interface for security tool execution adapters."""

    tool_name: str = "generic"

    @abstractmethod
    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        """Validate target format and input arguments."""
        pass

    @abstractmethod
    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        """Construct canonical execution command list."""
        pass

    @abstractmethod
    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse tool stdout/stderr into structured dictionary metadata."""
        pass
