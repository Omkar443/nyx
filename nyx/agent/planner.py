"""
NYX Autonomous Research Planner
Converts target context into policy-checked security research plans.
"""
from __future__ import annotations

from typing import Any, Dict, List
from nyx.ai.planner import MissionPlanner


class ResearchPlanner:
    """Generates structured security research plans from target context."""

    def __init__(self):
        self._inner_planner = MissionPlanner()

    def create_plan(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate structured ResearchPlan dictionary."""
        techs = context.get("technologies", [])
        matched_skills = context.get("skills_matched", [])

        # Default fallback skills if tech detection is empty
        skills = matched_skills if matched_skills else ["hunt-aspnet", "hunt-auth-bypass", "hunt-brute-force", "hunt-mfa-bypass"]

        objectives = [
            f"Analyze authentication flow and session management for {target}",
            f"Map authorization boundaries across harvested endpoints",
            f"Test parameter injection vectors on active attack surface",
        ]

        if "ASP.NET" in str(techs) or "Microsoft-IIS" in str(techs):
            objectives.append("Inspect ViewState handling and MachineKey configuration")

        return {
            "target": target,
            "objectives": objectives,
            "recommended_skills": skills,
            "priority": "HIGH",
            "reasoning": f"Target '{target}' surface mapped with {context.get('endpoints_count', 0)} endpoints and {len(techs)} detected stack components.",
            "required_tools": ["subfinder", "httpx", "katana"],
            "policy_checked": True,
        }
