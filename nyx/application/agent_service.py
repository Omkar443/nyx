"""
NYX Autonomous Agent Application Service
Orchestrates autonomous security research workflow, planning, decision tracking, and human approval.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from nyx.application.base import BaseService, ServiceResult
from nyx.agent import NYXAgent


class AgentService(BaseService):
    """Service facade for autonomous security research agent operations."""

    def __init__(self, provider_name: Optional[str] = None):
        super().__init__()
        self.agent = NYXAgent(provider_name=provider_name)

    def start_mission(self, target: str) -> ServiceResult:
        res = self.agent.start_mission(target)
        return self.ok(data=res, message=f"Started autonomous agent mission for target '{target}'.")

    def get_context(self, target: str) -> ServiceResult:
        res = self.agent.context_engine.get_agent_context(target)
        return self.ok(data=res, message=f"Retrieved reasoning context for '{target}'.")

    def plan_mission(self, target: str) -> ServiceResult:
        self.agent.target = target
        res = self.agent.plan()
        return self.ok(data=res.get("plan", {}), message=f"Generated research plan for '{target}'.")

    def propose_action(
        self,
        target: str,
        action: str,
        reason: str,
        tool_name: str = "subfinder",
        risk: str = "Medium",
        step: Optional[Dict[str, Any]] = None,
        impact_class: Optional[str] = None,
        impact_justification: Optional[str] = None,
    ) -> ServiceResult:
        self.agent.target = target
        res = self.agent.propose_action(
            action=action,
            reason=reason,
            tool_name=tool_name,
            risk=risk,
            step=step,
            impact_class=impact_class,
            impact_justification=impact_justification,
            target=target,
        )
        return self.ok(data=res, message=f"Proposed action '{res.get('action_id')}' for human approval.")

    def get_approvals(self) -> ServiceResult:
        pending = self.agent.approval_system.get_pending_approvals()
        return self.ok(data={"pending_count": len(pending), "pending": pending}, message=f"Retrieved {len(pending)} pending approvals.")

    def approve_action(self, action_id: str) -> ServiceResult:
        res = self.agent.approve_action(action_id)
        if not res.get("success"):
            return self.fail(message=res.get("error", "Approval failed."), error_code="APPROVAL_ERROR")
        return self.ok(data=res, message=f"Approved action '{action_id}'.")

    def deny_action(self, action_id: str, reason: str = "") -> ServiceResult:
        res = self.agent.deny_action(action_id, reason=reason)
        if not res.get("success"):
            return self.fail(message=res.get("error", "Denial failed."), error_code="DENIAL_ERROR")
        return self.ok(data=res, message=f"Denied action '{action_id}'.")

    def execute_action(self, action_id: str) -> ServiceResult:
        res = self.agent.execute(action_id)
        if not res.get("success"):
            return self.fail(message=res.get("error", "Execution failed."), error_code="EXECUTION_BLOCKED")
        return self.ok(data=res, message=f"Executed action '{action_id}'.")

    def get_status(self) -> ServiceResult:
        res = self.agent.get_status()
        return self.ok(data=res, message="Retrieved agent status.")
