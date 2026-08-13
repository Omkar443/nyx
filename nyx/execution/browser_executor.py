"""
NYX Browser Executor Harness
Executes approved browser actions requiring Approval ID verification, Target Scope validation, and Evidence tracking.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.security.scope import is_hostname_in_scope
from nyx.browser.controller import BrowserController
from nyx.application.evidence_service import EvidenceService


class BrowserExecutor:
    """Harness executing human-approved browser actions with scope validation and evidence logging."""

    def __init__(self, approval_system: Optional[Any] = None):
        if approval_system is None:
            from nyx.agent.approval import ApprovalSystem
            self.approval_system = ApprovalSystem()
        else:
            self.approval_system = approval_system

        self.browser_controller = BrowserController()
        self.evidence_service = EvidenceService()

    def execute_approved_browser_action(
        self,
        action_id: str,
        action_type: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        finding_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute approved browser navigation, form fill, or screenshot action."""
        # 1. Human Approval Verification
        if action_id not in self.approval_system._approved_actions:
            return {"success": False, "error": f"[APPROVAL ERROR] Action '{action_id}' was not approved or does not exist."}

        # 2. Scope Protocol Check
        if not is_hostname_in_scope(target):
            return {"success": False, "error": f"[SCOPE ERROR] Target '{target}' is not in authorized scope."}

        params = params or {}
        session = self.browser_controller.create_session(target=target)

        # 3. Action Execution
        result_data: Dict[str, Any] = {}
        act_norm = action_type.lower().strip()

        if act_norm == "navigate":
            url = params.get("url") or f"https://{target}"
            result_data = session.navigate(url)
        elif act_norm == "screenshot":
            result_data = session.capture_screenshot()
        elif act_norm == "har_capture":
            result_data = session.export_har()
        else:
            url = params.get("url") or f"https://{target}"
            result_data = session.navigate(url)

        # 4. Attach Evidence if finding_id provided
        evidence_info = None
        if finding_id:
            ev_res = self.evidence_service.add(
                finding_id=finding_id,
                ev_type="note",
                content=f"Executed browser action '{action_type}' for target '{target}'. Result: {result_data.get('status', 'COMPLETED')}",
                description=f"Browser execution trace for action '{action_type}'",
                source="browser_executor",
            )
            evidence_info = ev_res

        return {
            "success": True,
            "action_id": action_id,
            "action_type": action_type,
            "target": target,
            "session_id": session.context.session_id,
            "result": result_data,
            "evidence": evidence_info,
        }
