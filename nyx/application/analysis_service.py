"""
NYX Analysis Application Service
Orchestrates attack surface analysis, vulnerability classification, and technology mapping.
"""
from __future__ import annotations

from typing import Any
from nyx.core import analysis as core_analysis


class AnalysisService:
    """Service facade for surface analysis and classification."""

    def classify(self, target_url: str) -> dict[str, Any]:
        return core_analysis.classify_url(url=target_url)

    def analyze_surface(
        self, target: str, manifest: str | None = None
    ) -> dict[str, Any]:
        return core_analysis.get_surface(target=target, manifest=manifest)

    def technology_map(self, tech_name: str | None = None) -> dict[str, Any]:
        return core_analysis.get_technology_map(technology=tech_name)

    def get_decision_context(
        self, url: str, tech_stack: list[str] | None = None
    ) -> dict[str, Any]:
        return core_analysis.get_decision_context(
            url=url, tech_stack=tech_stack
        )
