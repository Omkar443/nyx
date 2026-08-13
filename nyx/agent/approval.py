"""
NYX Human Approval Control System
Enforces mandatory human sign-off before any active tool execution or probing can run.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class ApprovalSystem:
    """Manages human approval queue for proposed autonomous research actions."""

    def __init__(self):
        self._pending_queue: Dict[str, Dict[str, Any]] = {}
        self._approved_actions: Dict[str, Dict[str, Any]] = {}
        self._denied_actions: Dict[str, Dict[str, Any]] = {}

    def submit_for_approval(self, decision: Dict[str, Any]) -> str:
        """Submit a decision record to the pending human approval queue."""
        action_id = decision.get("action_id", "ACT-UNKNOWN")
        record = dict(decision)
        record["status"] = "PENDING_APPROVAL"
        self._pending_queue[action_id] = record
        return action_id

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Return list of all pending approval requests."""
        return list(self._pending_queue.values())

    def approve_action(self, action_id: str) -> tuple[bool, str, Optional[Dict[str, Any]]]:
        """Approve a pending action ID."""
        if action_id not in self._pending_queue:
            return False, f"Action ID '{action_id}' not found in pending approval queue.", None

        record = self._pending_queue.pop(action_id)
        record["status"] = "APPROVED"
        self._approved_actions[action_id] = record
        return True, f"Action '{action_id}' approved successfully.", record

    def deny_action(self, action_id: str, reason: str = "") -> tuple[bool, str]:
        """Deny a pending action ID."""
        if action_id not in self._pending_queue:
            return False, f"Action ID '{action_id}' not found in pending approval queue."

        record = self._pending_queue.pop(action_id)
        record["status"] = "DENIED"
        record["denial_reason"] = reason or "User explicitly denied action."
        self._denied_actions[action_id] = record
        return True, f"Action '{action_id}' denied."
