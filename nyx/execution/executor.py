"""
NYX Controlled Tool Execution Engine
Delegates tool execution to ExecutionEngine for backward compatibility.
"""
from __future__ import annotations

from nyx.models.execution import ExecutionResult
from nyx.execution.engine import ExecutionEngine


def log_execution_to_db(result: ExecutionResult) -> None:
    engine = ExecutionEngine()
    engine.log_execution_to_db(result)


def execute_tool(
    tool_name: str,
    target: str,
    extra_args: list[str] | None = None,
    dry_run: bool = False,
    active_permitted: bool = False,
) -> ExecutionResult:
    engine = ExecutionEngine()
    return engine.execute(
        tool_name=tool_name,
        target=target,
        arguments=extra_args,
        dry_run=dry_run,
        active_permitted=active_permitted,
    )
