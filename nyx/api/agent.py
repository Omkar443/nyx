"""
NYX Agent API Endpoint Interface
Provides programmatic endpoint functions for external AI agents (Antigravity, NYX AI, GPT, Gemini, MCP).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.ai.context import ContextEngine
from nyx.ai.planner import MissionPlanner
from nyx.application.execution_service import ExecutionService
from nyx.application.finding_service import FindingService
from nyx.application.recon_service import ReconService
from nyx.application.skill_service import SkillService


def get_target_context(target: str) -> Dict[str, Any]:
    """Retrieve structured security context for a target."""
    engine = ContextEngine()
    return engine.get_target_context(target)


def list_skills(category: Optional[str] = None) -> Dict[str, Any]:
    """List available NYX security research skills."""
    svc = SkillService()
    res = svc.get_skills_result(category=category)
    return res.to_dict()


def run_recon(target: str) -> Dict[str, Any]:
    """Run passive reconnaissance workflow."""
    svc = ReconService()
    res = svc.run_recon(target)
    return res.to_dict()


def execute_tool(
    tool_name: str,
    target: str,
    arguments: Optional[List[str]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Execute a controlled security tool."""
    svc = ExecutionService()
    res = svc.run_tool(tool_name, target, arguments=arguments, dry_run=dry_run)
    return res.to_dict()


def validate_finding(finding_id: str) -> Dict[str, Any]:
    """Validate a finding hypothesis against empirical verification rules."""
    svc = FindingService()
    res = svc.get_finding(finding_id)
    return res.to_dict()


def generate_report(finding_id: str, platform: str = "bugcrowd") -> Dict[str, Any]:
    """Generate platform-formatted security research report."""
    svc = FindingService()
    res = svc.report(finding_id=finding_id, platform=platform)
    return res.to_dict()


def plan_mission(target: str, provider_name: Optional[str] = None) -> Dict[str, Any]:
    """Plan a policy-validated multi-step mission using AI reasoning."""
    planner = MissionPlanner()
    return planner.create_plan(target, provider_name=provider_name)
