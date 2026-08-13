"""
NYX Security Engine Execution API
Structured programmatic API interface for AI agent orchestration (Antigravity, NYX AI, GPT, Gemini, MCP).
"""
from __future__ import annotations

from typing import Any
from nyx.application.execution_service import ExecutionService


def run_execution(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Programmatic execution API endpoint for autonomous AI agents.
    
    Payload schema:
    {
        "action": "run_tool" | "run_recon",
        "tool": "subfinder" | "httpx" | ...,
        "target": "example.com",
        "arguments": ["-silent"],
        "dry_run": false,
        "active_permitted": false
    }
    """
    svc = ExecutionService()
    tool = payload.get("tool") or payload.get("tool_name") or "subfinder"
    target = payload.get("target") or payload.get("url") or ""
    args = payload.get("arguments") or payload.get("args") or []
    dry_run = bool(payload.get("dry_run", False))
    active_permitted = bool(payload.get("active_permitted", False))

    res = svc.run_tool(
        tool_name=tool,
        target=target,
        arguments=args,
        dry_run=dry_run,
        active_permitted=active_permitted,
    )
    return res.to_dict()


def get_execution_status_api(execution_id: str) -> dict[str, Any]:
    """API endpoint to query status and artifacts of an execution ID."""
    svc = ExecutionService()
    res = svc.get_status(execution_id)
    return res.to_dict()


def list_execution_history_api(limit: int = 50) -> dict[str, Any]:
    """API endpoint to query execution history records."""
    svc = ExecutionService()
    res = svc.get_history(limit=limit)
    return res.to_dict()
