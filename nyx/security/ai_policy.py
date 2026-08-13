"""
NYX AI Security Policy Engine
Enforces security boundary rules, scope restrictions, authorization checks, and execution permissions on AI actions.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.security.authorization import check_authorization, is_hostname_in_scope


class AIPolicyEngine:
    """Policy control engine governing AI reasoning and mission execution."""

    DEFAULT_POLICY = {
        "allow": {
            "passive_recon": True,
            "technology_mapping": True,
            "endpoint_harvesting": True,
            "report_generation": True,
            "finding_triage": True,
        },
        "require_confirmation": {
            "active_scanning": True,
            "exploitation": True,
            "payload_injection": True,
            "credential_testing": True,
        },
        "block": {
            "out_of_scope_targets": True,
            "unauthorized_testing": True,
            "third_party_saas": True,
            "pii_exfiltration": True,
        },
    }

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir

    def get_policy(self) -> Dict[str, Any]:
        """Load active policy or return default."""
        d = _get_eng_dir(create=False, base_dir=self.base_dir)
        if d.exists():
            pf = d / "ai_policy.json"
            if pf.exists():
                try:
                    return json.loads(pf.read_text(encoding="utf-8"))
                except Exception:
                    pass
        return self.DEFAULT_POLICY

    def check_action_permitted(
        self,
        action_type: str,
        target: str,
        active_permitted: bool = False,
    ) -> Tuple[bool, str]:
        """Verify if an AI-proposed action is permitted under security policies."""
        # 1. Authorization check
        auth_ok, auth_err = check_authorization(base_dir=self.base_dir)
        if not auth_ok:
            return False, f"[SECURITY BLOCKED] Authorization check failed: {auth_err}"

        # 2. Scope check
        if not is_hostname_in_scope(target, base_dir=self.base_dir):
            return False, f"[SCOPE BLOCKED] Target '{target}' is outside engagement scope boundaries."

        # 3. Policy category check
        norm_action = action_type.lower()
        policy = self.get_policy()

        # Check explicit blocks
        if norm_action in policy.get("block", {}):
            return False, f"[POLICY BLOCKED] Action '{action_type}' is explicitly blocked by AI policy."

        # Check confirmation requirement for active steps
        req_conf = policy.get("require_confirmation", {})
        if norm_action in req_conf and req_conf[norm_action] and not active_permitted:
            return False, f"[POLICY CONFIRMATION REQUIRED] Active action '{action_type}' requires explicit active permission."

        return True, "Action permitted."

    def filter_plan_steps(self, target: str, steps: List[Dict[str, Any]], active_permitted: bool = False) -> List[Dict[str, Any]]:
        """Filter plan steps according to security policies."""
        filtered = []
        for step in steps:
            action = step.get("action", "unknown")
            step_target = step.get("target") or target
            ok, msg = self.check_action_permitted(action, step_target, active_permitted=active_permitted)
            step_copy = dict(step)
            step_copy["permitted"] = ok
            step_copy["policy_status"] = "PERMITTED" if ok else "BLOCKED"
            step_copy["policy_reason"] = msg
            filtered.append(step_copy)
        return filtered
