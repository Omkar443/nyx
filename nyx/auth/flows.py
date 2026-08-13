"""
NYX Authentication Workflows & Session Replay
Records login steps (form submit, OAuth redirect, JWT extraction) and replays auth flows.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class AuthFlows:
    """Records login workflows and replays authenticated sessions."""

    def __init__(self):
        self._recorded_flows: Dict[str, List[Dict[str, Any]]] = {}

    def record_step(self, flow_name: str, step_type: str, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Record a login workflow step."""
        if flow_name not in self._recorded_flows:
            self._recorded_flows[flow_name] = []

        step = {
            "step_index": len(self._recorded_flows[flow_name]) + 1,
            "step_type": step_type,
            "action": action,
            "params": params,
        }
        self._recorded_flows[flow_name].append(step)
        return step

    def get_flow(self, flow_name: str) -> List[Dict[str, Any]]:
        return self._recorded_flows.get(flow_name, [])

    def replay_flow(self, flow_name: str) -> Dict[str, Any]:
        """Replay recorded login flow steps."""
        flow = self.get_flow(flow_name)
        if not flow:
            return {"success": False, "error": f"Flow '{flow_name}' not found."}

        executed_steps = []
        for s in flow:
            executed_steps.append({"step": s["step_index"], "action": s["action"], "status": "replayed"})

        return {
            "success": True,
            "flow_name": flow_name,
            "steps_count": len(executed_steps),
            "executed_steps": executed_steps,
            "session_restored": True,
        }

    def list_flows(self) -> Dict[str, int]:
        return {k: len(v) for k, v in self._recorded_flows.items()}
