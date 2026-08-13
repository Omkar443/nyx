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
    ) -> Dict[str, Any]:
        """Propose an active execution action for human approval."""
        decision = self.decision_engine.create_decision(
            target=self.target or "example.com",
            action=action,
            reason=reason,
            confidence=confidence,
            risk=risk,
            tool_name=tool_name,
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
        """Approve a pending action ID."""
        ok, msg, record = self.approval_system.approve_action(action_id)
        if not ok:
            return {"success": False, "error": msg}
        return {"success": True, "message": msg, "record": record}

    def deny_action(self, action_id: str, reason: str = "") -> Dict[str, Any]:
        """Deny a pending action ID."""
        ok, msg = self.approval_system.deny_action(action_id, reason=reason)
        if not ok:
            return {"success": False, "error": msg}
        self.state_machine.transition_to("PLANNING")
        return {"success": True, "message": msg}

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
