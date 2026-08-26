"""
NYX AI Application Service Facade
Exposes AI reasoning, context engine, mission planning, and provider management through standard ServiceResult containers.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from nyx.application.base import BaseService, ServiceResult
from nyx.ai.manager import AIManager
from nyx.ai.context import ContextEngine
from nyx.ai.planner import MissionPlanner
from nyx.ai.memory import AIMemory


class AIService(BaseService):
    """Application service facade for AI orchestration & integration."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir
        self.manager = AIManager()
        self.context_engine = ContextEngine(base_dir=base_dir)
        self.planner = MissionPlanner(base_dir=base_dir)
        self.memory = AIMemory(base_dir=base_dir)

    def list_providers(self) -> ServiceResult:
        """List registered AI providers."""
        try:
            providers = self.manager.list_providers()
            return self.ok(data={"providers": providers, "active": self.manager.active_provider_name})
        except Exception as ex:
            return self.fail(message=f"Error listing AI providers: {ex}", error_code="PROVIDER_ERROR")

    def set_active_provider(self, provider_name: str) -> ServiceResult:
        """Switch active AI provider."""
        try:
            ok = self.manager.set_active_provider(provider_name)
            if ok:
                return self.ok(data={"active": self.manager.active_provider_name}, message=f"Active AI provider set to '{provider_name}'.")
            return self.fail(message=f"Provider '{provider_name}' not found.", error_code="INVALID_PROVIDER")
        except Exception as ex:
            return self.fail(message=f"Error setting active provider: {ex}", error_code="PROVIDER_ERROR")

    def test_provider(self, provider_name: Optional[str] = None) -> ServiceResult:
        """Run health check test for specified AI provider."""
        try:
            res = self.manager.test_provider(name=provider_name)
            if res.get("success"):
                return self.ok(data=res, message=res.get("message", "Provider test passed."))
            return self.fail(message=res.get("message", "Provider test failed."), error_code="PROVIDER_TEST_FAILED", details=res)
        except Exception as ex:
            return self.fail(message=f"Error testing AI provider: {ex}", error_code="PROVIDER_ERROR")

    def get_context(self, target: str) -> ServiceResult:
        """Retrieve aggregated security context for a target."""
        try:
            ctx = self.context_engine.get_target_context(target)
            return self.ok(data=ctx, message=f"Generated context for target '{target}'.")
        except Exception as ex:
            return self.fail(message=f"Error generating context: {ex}", error_code="CONTEXT_ERROR")

    def plan_mission(self, target: str, provider_name: Optional[str] = None) -> ServiceResult:
        """Generate a policy-validated security mission plan."""
        try:
            plan = self.planner.create_plan(target, provider_name=provider_name)
            if plan.get("status") == "error":
                return self.fail(
                    message=plan.get("error", "Mission plan generation failed."),
                    error_code="SCOPE_ERROR",
                    details=plan,
                )
            return self.ok(data=plan, message=f"Mission plan generated for '{target}'.")
        except Exception as ex:
            return self.fail(message=f"Error generating mission plan: {ex}", error_code="PLANNER_ERROR")

    def execute_mission(
        self,
        target: str,
        provider_name: Optional[str] = None,
        active_permitted: bool = False,
    ) -> ServiceResult:
        """Execute a policy-validated security mission plan."""
        try:
            plan = self.planner.create_plan(
                target,
                provider_name=provider_name,
                active_permitted=active_permitted,
            )
            if plan.get("status") == "error":
                return self.fail(
                    message=plan.get("error", "Mission plan generation failed."),
                    error_code="SCOPE_ERROR",
                    details=plan,
                )
            exec_res = self.planner.execute_plan(
                plan,
                active_permitted=active_permitted,
            )
            if exec_res.get("status") == "error":
                return self.fail(
                    message=exec_res.get("error", "Mission execution failed."),
                    error_code="EXECUTION_FAILED",
                    details=exec_res,
                )
            return self.ok(data=exec_res, message=f"Mission executed for '{target}'.")
        except Exception as ex:
            return self.fail(message=f"Error executing mission plan: {ex}", error_code="PLANNER_ERROR")

    def get_status(self) -> ServiceResult:
        """Retrieve overall AI orchestration status."""
        try:
            decisions = self.memory.get_decisions(limit=10)
            failed = self.memory.get_failed_approaches()
            return self.ok(
                data={
                    "active_provider": self.manager.active_provider_name,
                    "registered_providers": [p["name"] for p in self.manager.list_providers()],
                    "recent_decisions_count": len(decisions),
                    "failed_approaches_count": len(failed),
                },
                message="AI status retrieved successfully.",
            )
        except Exception as ex:
            return self.fail(message=f"Error getting AI status: {ex}", error_code="STATUS_ERROR")
