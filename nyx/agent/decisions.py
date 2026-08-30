"""
NYX Agent Decision Tracking Engine
Tracks explainable AI decision records and proposed execution actions.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List


class DecisionEngine:
    """Generates explainable decision logs for proposed security research actions."""

    def create_decision(
        self,
        target: str,
        action: str,
        reason: str,
        confidence: int = 85,
        risk: str = "Medium",
        evidence_required: List[str] | None = None,
        tool_name: str = "subfinder",
        step: Dict[str, Any] | None = None,
        impact_class: str | None = None,
        impact_justification: str | None = None,
    ) -> Dict[str, Any]:
        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        
        return {
            "action_id": action_id,
            "target": target,
            "action": action,
            "tool_name": tool_name,
            "tool": tool_name,
            "reason": reason,
            "confidence": max(1, min(100, confidence)),
            "risk": risk,
            "impact_class": impact_class or (step.get("impact_class") if step else None) or ("DESTRUCTIVE" if risk.upper() in ("HIGH", "CRITICAL") else "NON_DESTRUCTIVE"),
            "impact_justification": impact_justification or (step.get("impact_justification") if step else None) or reason,
            "step": step,
            "evidence_required": evidence_required or ["request", "response", "differential_access"],
            "timestamp": datetime.now().isoformat(),
            "status": "PROPOSED",
        }
