"""
NYX Human Approval Control System
Enforces mandatory human sign-off before any active tool execution or probing can run.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ApprovalSystem:
    """Manages human approval queue for proposed autonomous research actions."""

    # Class-level store for cross-instance and API-service consistency
    _shared_pending_queue: Dict[str, Dict[str, Any]] = {}
    _shared_approved_actions: Dict[str, Dict[str, Any]] = {}
    _shared_denied_actions: Dict[str, Dict[str, Any]] = {}

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir
        if base_dir is not None:
            self._pending_queue: Dict[str, Dict[str, Any]] = {}
            self._approved_actions: Dict[str, Dict[str, Any]] = {}
            self._denied_actions: Dict[str, Dict[str, Any]] = {}
        else:
            self._pending_queue = self._shared_pending_queue
            self._approved_actions = self._shared_approved_actions
            self._denied_actions = self._shared_denied_actions
        self._load_persisted()

    def _get_approvals_file(self) -> Optional[Path]:
        if not self.base_dir:
            from nyx.core.engagement import _get_eng_dir
            d = _get_eng_dir(create=False)
            return (d / "approvals.json") if d.exists() else None
        d = self.base_dir / ".engagement"
        return (d / "approvals.json") if d.exists() else None

    def _load_persisted(self) -> None:
        try:
            f = self._get_approvals_file()
            if f and f.exists():
                data = json.loads(f.read_text(encoding="utf-8"))
                for k, v in data.get("approved", {}).items():
                    self._approved_actions[k] = v
                    self._pending_queue.pop(k, None)
                for k, v in data.get("denied", {}).items():
                    self._denied_actions[k] = v
                    self._pending_queue.pop(k, None)
                for k, v in data.get("pending", {}).items():
                    if k not in self._approved_actions and k not in self._denied_actions:
                        self._pending_queue[k] = v
        except Exception:
            pass

    def _save_persisted(self) -> None:
        try:
            f = self._get_approvals_file()
            if f:
                payload = {
                    "pending": self._pending_queue,
                    "approved": self._approved_actions,
                    "denied": self._denied_actions,
                }
                f.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    def submit_for_approval(self, decision: Dict[str, Any]) -> str:
        """Submit a decision record to the pending human approval queue."""
        from datetime import datetime, timezone
        action_id = decision.get("action_id", "ACT-UNKNOWN")
        record = dict(decision)
        record["status"] = "PENDING_APPROVAL"
        if "created_at" not in record or not record["created_at"]:
            record["created_at"] = datetime.now(timezone.utc).isoformat()
        
        # Ensure full step metadata is preserved
        step = record.get("step")
        if isinstance(step, dict):
            record["tool"] = record.get("tool") or step.get("tool") or record.get("tool_name")
            record["tool_name"] = record.get("tool_name") or step.get("tool") or record.get("tool")
            record["action"] = record.get("action") or step.get("action") or step.get("name")
            record["name"] = record.get("name") or step.get("name") or step.get("action")
            record["impact_class"] = record.get("impact_class") or step.get("impact_class") or "DESTRUCTIVE"
            record["impact_justification"] = record.get("impact_justification") or step.get("impact_justification") or step.get("description")
            record["target"] = record.get("target") or step.get("target")
            record["params"] = record.get("params") or step.get("params") or {}
        
        self._pending_queue[action_id] = record
        self._save_persisted()
        return action_id

    def expire_stale_approvals(
        self,
        target: Optional[str] = None,
        exclude_action_id: Optional[str] = None,
        reason: str = "Superseded by new autonomous mission run",
    ) -> int:
        """Expire leftover pending actions for a target or globally."""
        self._load_persisted()
        expired_keys = []
        for k, v in list(self._pending_queue.items()):
            if exclude_action_id and k == exclude_action_id:
                continue
            if target:
                tgt = v.get("mission_target") or v.get("target") or ""
                t_clean = target.strip("/").lower()
                tgt_clean = tgt.strip("/").lower()
                if t_clean and tgt_clean and (t_clean in tgt_clean or tgt_clean in t_clean):
                    expired_keys.append(k)
            else:
                expired_keys.append(k)

        for k in expired_keys:
            rec = self._pending_queue.pop(k, None)
            if rec:
                rec["status"] = "EXPIRED"
                rec["denial_reason"] = reason
                self._denied_actions[k] = rec

        if expired_keys:
            self._save_persisted()
        return len(expired_keys)

    def get_pending_approvals(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return list of all pending approval requests, optionally filtered by target."""
        self._load_persisted()
        items = list(self._pending_queue.values())
        if not target:
            return items
        from nyx.ai.context import _matches_target_endpoint

        def _is_match(t_val: str, tgt: str) -> bool:
            if not t_val or not tgt:
                return False
            t_clean = t_val.strip("/").lower()
            tgt_clean = tgt.strip("/").lower()
            if t_clean in tgt_clean or tgt_clean in t_clean:
                return True
            return _matches_target_endpoint(t_val, tgt) or _matches_target_endpoint(tgt, t_val)

        return [
            rec for rec in items
            if _is_match(rec.get("mission_target") or rec.get("target") or "", target)
        ]

    def approve_action(self, action_id: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Approve a pending action ID."""
        self._load_persisted()
        if action_id not in self._pending_queue:
            return False, f"Action ID '{action_id}' not found in pending approval queue.", None

        record = self._pending_queue.pop(action_id)
        record["status"] = "APPROVED"
        self._approved_actions[action_id] = record
        self._save_persisted()
        return True, f"Action '{action_id}' approved successfully.", record

    def deny_action(self, action_id: str, reason: str = "") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Deny a pending action ID."""
        self._load_persisted()
        if action_id not in self._pending_queue:
            return False, f"Action ID '{action_id}' not found in pending approval queue.", None

        record = self._pending_queue.pop(action_id)
        record["status"] = "DENIED"
        record["denial_reason"] = reason or "User explicitly denied action."
        self._denied_actions[action_id] = record
        self._save_persisted()
        return True, f"Action '{action_id}' denied.", record
