"""
NYX Mission Reasoning Engine & Planner
Converts AI decisions into structured, policy-validated NYX security missions.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from nyx.ai.context import ContextEngine
from nyx.ai.manager import AIManager
from nyx.ai.memory import AIMemory
from nyx.security.ai_policy import AIPolicyEngine


class MissionPlanner:
    """Converts high-level AI analysis into structured, policy-validated security missions."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir
        self.context_engine = ContextEngine(base_dir=base_dir)
        self.ai_manager = AIManager()
        self.policy_engine = AIPolicyEngine(base_dir=base_dir)
        self.memory = AIMemory(base_dir=base_dir)

    def create_plan(
        self,
        target: str,
        provider_name: Optional[str] = None,
        active_permitted: bool = False,
    ) -> Dict[str, Any]:
        """Generate a structured multi-step security mission for a target."""
        context = self.context_engine.get_target_context(target)

        # 1. Obtain AI Provider Reasoning
        analysis = self.ai_manager.analyze(context, provider_name=provider_name)
        provider_info = self.ai_manager.get_provider(provider_name).get_info()

        # 2. Build Standard Mission Steps
        raw_steps = [
            {
                "step": 1,
                "name": "Technology Fingerprinting",
                "action": "passive_recon",
                "tool": "httpx",
                "description": "Probe live host, HTTP headers, titles, and technology stack.",
            },
            {
                "step": 2,
                "name": "Endpoint & Parameter Harvesting",
                "action": "endpoint_harvesting",
                "tool": "katana",
                "description": "Crawl public JS bundles and endpoint surface.",
            },
            {
                "step": 3,
                "name": "Attack Surface Mapping & Skill Matching",
                "action": "technology_mapping",
                "tool": "nyx-classify",
                "description": "Match detected technologies to specialized NYX security skills.",
            },
            {
                "step": 4,
                "name": "Controlled Vulnerability Triage",
                "action": "finding_triage",
                "tool": "nyx-triage",
                "description": "Validate vulnerability hypotheses against empirical evidence rules.",
            },
        ]

        # 3. Policy Gate Validation
        validated_steps = self.policy_engine.filter_plan_steps(target, raw_steps, active_permitted=active_permitted)

        plan = {
            "target": target,
            "provider": provider_info.get("name"),
            "phase": context.get("phase", "DISCOVERY"),
            "analysis": analysis.get("analysis", ""),
            "recommended_focus": analysis.get("recommended_focus", ""),
            "steps": validated_steps,
            "total_steps": len(validated_steps),
            "valid": all(s.get("permitted", False) for s in validated_steps),
        }

        # 4. Record decision in AI Memory
        self.memory.record_decision(
            decision_type="MISSION_PLAN",
            details={"target": target, "provider": provider_info.get("name"), "valid": plan["valid"]},
        )

        return plan

    def validate_plan(self, plan: Dict[str, Any], active_permitted: bool = False) -> Tuple[bool, str]:
        """Validate an existing mission plan against policy and scope rules."""
        target = plan.get("target", "")
        if not target:
            return False, "Plan missing target."

        steps = plan.get("steps", [])
        if not steps:
            return False, "Plan contains no execution steps."

        for step in steps:
            action = step.get("action", "unknown")
            step_target = step.get("target") or target
            ok, err = self.policy_engine.check_action_permitted(action, step_target, active_permitted=active_permitted)
            if not ok:
                return False, f"Step '{step.get('name')}' rejected: {err}"

        return True, "Plan validated successfully under policy gates."

    def execute_plan(self, plan: Dict[str, Any], active_permitted: bool = False) -> Dict[str, Any]:
        """Execute a validated mission plan using Application Services."""
        valid, msg = self.validate_plan(plan, active_permitted=active_permitted)
        if not valid:
            return {"status": "error", "error": msg, "executed_steps": 0}

        results = []
        target = plan.get("target", "")
        from nyx.application.execution_service import ExecutionService

        svc = ExecutionService(base_dir=self.base_dir)

        for step in plan.get("steps", []):
            tool = step.get("tool")
            if tool in ("httpx", "subfinder", "katana", "nuclei", "nmap"):
                res = svc.run_tool(tool, target, dry_run=True, active_permitted=active_permitted)
                results.append({"step": step.get("step"), "name": step.get("name"), "result": res.to_dict()})
            else:
                results.append({"step": step.get("step"), "name": step.get("name"), "result": {"status": "success", "simulated": True}})

        return {
            "status": "success",
            "target": target,
            "executed_steps": len(results),
            "step_results": results,
        }
