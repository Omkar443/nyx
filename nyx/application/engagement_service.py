"""
NYX Engagement Application Service
Orchestrates engagement workspace lifecycle, state transitions, and memory persistence.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from nyx.core import engagement as core_engagement


class EngagementService:
    """Service facade for engagement workspace operations."""

    def init_engagement(self, target: str, reset: bool = False, force: bool = False) -> dict[str, Any]:
        return core_engagement.init_engagement(target=target, reset=reset, force=force)

    def get_status(self) -> dict[str, Any]:
        return core_engagement.get_engagement_status()

    def set_state(self, new_state: str | None = None, mode: str | None = None, force: bool = False) -> dict[str, Any]:
        return core_engagement.set_engagement_state(new_state=new_state, mode=mode, force_state=force)

    def export_engagement(self) -> dict[str, Any]:
        return core_engagement.export_engagement()

    def add_memory(self, type_: str, value: str, source: str = "manual", priority: str = "P2", category: str = "frameworks") -> dict[str, Any]:
        return core_engagement.add_memory(mem_type=type_, value=value, source=source, priority=priority, category=category)

    def search_memory(self, query: str) -> dict[str, Any]:
        return core_engagement.search_memory(query=query)

    def import_burp_xml(self, xml_file: str | Path, include_out_of_scope: bool = False) -> dict[str, Any]:
        return core_engagement.import_burp_xml(xml_file=xml_file, include_out_of_scope=include_out_of_scope)
