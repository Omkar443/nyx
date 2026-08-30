"""
NYX Autonomous Security Research Agent Orchestrator
Main entry point coordinating context analysis, planning, reasoning, human approval gates, and tool execution.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from nyx.agent.state import AgentStateMachine
from nyx.agent.context import AgentContextEngine
from nyx.agent.planner import ResearchPlanner
from nyx.agent.decisions import DecisionEngine
from nyx.agent.approval import ApprovalSystem
from nyx.agent.memory import AgentMemory
from nyx.agent.reasoning import ReasoningEngine
from nyx.application.execution_service import ExecutionService
from nyx.application.finding_service import FindingService


class NYXAgent:
    """Controlled autonomous security research agent."""

    def __init__(self, provider_name: Optional[str] = None):
        self.state_machine = AgentStateMachine(initial_state="IDLE")
        self.context_engine = AgentContextEngine()
        self.planner = ResearchPlanner()
        self.decision_engine = DecisionEngine()
        self.approval_system = ApprovalSystem()
        self.memory = AgentMemory()
        self.reasoning_engine = ReasoningEngine(provider_name=provider_name)
        self.execution_service = ExecutionService()
        self.finding_service = FindingService()
        self.target: Optional[str] = None
        self.active_context: Optional[Dict[str, Any]] = None
        self.active_plan: Optional[Dict[str, Any]] = None

    def start_mission(self, target: str) -> Dict[str, Any]:
        """Start autonomous research mission for a target."""
        self.target = target
        self.state_machine.transition_to("ANALYZING", force=True)
        return {
            "status": "started",
            "target": target,
            "agent_state": self.state_machine.current_state,
        }

    def analyze(self) -> Dict[str, Any]:
        """Perform context analysis on target."""
        if not self.target:
            self.target = "example.com"
        
        self.state_machine.transition_to("ANALYZING", force=True)
        self.active_context = self.context_engine.get_agent_context(self.target)
        analysis_res = self.reasoning_engine.analyze_target(self.target, self.active_context)
        
        return {
            "status": "completed",
            "target": self.target,
            "agent_state": self.state_machine.current_state,
            "context": self.active_context,
            "analysis": analysis_res,
        }

    def plan(self) -> Dict[str, Any]:
        """Generate structured research plan."""
        if not self.active_context:
            self.analyze()
        
        self.state_machine.transition_to("PLANNING")
        self.active_plan = self.planner.create_plan(self.target or "example.com", self.active_context or {})
        self.memory.record_plan(self.active_plan)
        
        return {
            "status": "completed",
            "target": self.target,
            "agent_state": self.state_machine.current_state,
            "plan": self.active_plan,
        }

    def propose_action(
        self,
        action: str,
        reason: str,
        tool_name: str = "subfinder",
        risk: str = "Medium",
        confidence: int = 85,
        step: Dict[str, Any] | None = None,
        impact_class: str | None = None,
        impact_justification: str | None = None,
        target: str | None = None,
    ) -> Dict[str, Any]:
        """Propose an active execution action for human approval."""
        eff_target = target or self.target or "example.com"
        decision = self.decision_engine.create_decision(
            target=eff_target,
            action=action,
            reason=reason,
            confidence=confidence,
            risk=risk,
            tool_name=tool_name,
            step=step,
            impact_class=impact_class,
            impact_justification=impact_justification,
        )
        
        action_id = self.approval_system.submit_for_approval(decision)
        self.memory.record_decision(decision)
        self.state_machine.transition_to("WAITING_APPROVAL")
        
        return {
            "status": "proposed",
            "action_id": action_id,
            "agent_state": self.state_machine.current_state,
            "decision": decision,
        }

    def approve_action(self, action_id: str) -> Dict[str, Any]:
        """Approve a pending action ID and execute the step with active_permitted=True."""
        ok, msg, record = self.approval_system.approve_action(action_id)
        if not ok:
            return {"success": False, "error": msg}

        rec = record or {}
        target = rec.get("target") or self.target or "example.com"
        step = rec.get("step")
        if not step or not isinstance(step, dict):
            step = {
                "step": 1,
                "name": rec.get("action") or rec.get("name") or "Approved Action",
                "tool": rec.get("tool_name") or rec.get("tool") or "nuclei",
                "action": rec.get("action") or "custom_exec",
                "impact_class": rec.get("impact_class") or "DESTRUCTIVE",
                "impact_justification": rec.get("impact_justification") or rec.get("reason"),
                "reason": rec.get("reason"),
                "target": target,
                "params": rec.get("params") or {},
            }

        # Actually execute the approved step via MissionPlanner with active_permitted=True
        from nyx.ai.planner import MissionPlanner
        planner = MissionPlanner(base_dir=getattr(self, "base_dir", None))
        step_result = planner.execute_step(step=step, target=target, active_permitted=True)

        self.state_machine.transition_to("VALIDATING")
        return {
            "success": True,
            "message": f"Action '{action_id}' approved and executed.",
            "action_id": action_id,
            "record": rec,
            "execution_result": step_result,
            "result": step_result.get("result") if isinstance(step_result, dict) else step_result,
            "status": "approved_and_executed",
        }

    def deny_action(self, action_id: str, reason: str = "") -> Dict[str, Any]:
        """Deny a pending action ID and persist its exclusion into engagement memory."""
        ok, msg, record = self.approval_system.deny_action(action_id, reason=reason)
        if not ok:
            return {"success": False, "error": msg}

        rec = record or {}
        target = rec.get("target") or self.target or "example.com"
        tool = rec.get("tool_name") or rec.get("tool")
        action = rec.get("action")
        rec_reason = rec.get("reason")
        name = rec.get("name")
        step = rec.get("step") if isinstance(rec.get("step"), dict) else {}

        # Persist identifying features so future candidate generation excludes it
        from nyx.core.engagement import add_memory
        base_dir = getattr(self, "base_dir", None)
        if tool:
            add_memory(type_="vector", value=f"{tool}_execution", endpoint=target, result="denied_by_operator", base_dir=base_dir)
        if action:
            add_memory(type_="vector", value=f"{action}_execution", endpoint=target, result="denied_by_operator", base_dir=base_dir)
            add_memory(type_="vector", value=str(action).lower(), endpoint=target, result="denied_by_operator", base_dir=base_dir)
        if rec_reason:
            add_memory(type_="vector", value=str(rec_reason).lower(), endpoint=target, result="denied_by_operator", base_dir=base_dir)
        if name or step.get("name"):
            n = name or step.get("name")
            add_memory(type_="vector", value=str(n).lower(), endpoint=target, result="denied_by_operator", base_dir=base_dir)
        if step.get("tool"):
            add_memory(type_="vector", value=f"{step.get('tool')}_execution", endpoint=target, result="denied_by_operator", base_dir=base_dir)
        if step.get("action"):
            add_memory(type_="vector", value=f"{step.get('action')}_execution", endpoint=target, result="denied_by_operator", base_dir=base_dir)

        self.state_machine.transition_to("PLANNING")
        return {"success": True, "message": msg, "action_id": action_id, "status": "denied"}

    def execute(self, action_id: str) -> Dict[str, Any]:
        """Execute an approved action ID."""
        if action_id in [a["action_id"] for a in self.approval_system.get_pending_approvals()]:
            return {
                "success": False,
                "error": f"Action '{action_id}' is pending approval. Human sign-off required.",
                "policy_blocked": True,
            }

        approved_record = self.approval_system._approved_actions.get(action_id)
        if not approved_record:
            return {
                "success": False,
                "error": f"Action '{action_id}' was not approved or does not exist.",
                "policy_blocked": True,
            }

        self.state_machine.transition_to("EXECUTING")
        tool_name = approved_record.get("tool_name", "subfinder")
        
        res = self.execution_service.run_tool(
            tool_name=tool_name,
            target=self.target or "example.com",
            dry_run=True,
        )
        
        self.state_machine.transition_to("VALIDATING")
        return {
            "success": True,
            "action_id": action_id,
            "agent_state": self.state_machine.current_state,
            "execution_result": res.to_dict() if hasattr(res, "to_dict") else res,
        }

    def get_status(self) -> Dict[str, Any]:
        """Get current agent status and pending approval queue."""
        return {
            "target": self.target,
            "agent_state": self.state_machine.current_state,
            "pending_approvals_count": len(self.approval_system.get_pending_approvals()),
            "pending_approvals": self.approval_system.get_pending_approvals(),
        }
