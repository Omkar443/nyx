"""
NYX Execution Application Service
Service facade for security tool orchestration, execution queue management, and artifact history.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nyx.application.base import BaseService, ServiceResult
from nyx.execution.engine import ExecutionEngine
from nyx.execution.artifacts import get_execution_artifacts
from nyx.execution.queue import ExecutionQueue
from nyx.models.execution import ExecutionRequest, ExecutionStatus
from nyx.infrastructure.filesystem import _get_eng_dir


class ExecutionService(BaseService):
    """Application service facade for tool execution lifecycle & orchestration."""

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir
        self.engine = ExecutionEngine(base_dir=base_dir)
        self.queue = ExecutionQueue(base_dir=base_dir)

    def run_tool(
        self,
        tool_name: str,
        target: str,
        arguments: list[str] | None = None,
        dry_run: bool = False,
        active_permitted: bool = False,
    ) -> ServiceResult:
        """Run a security tool through the execution engine."""
        try:
            res = self.engine.execute(
                tool_name=tool_name,
                target=target,
                arguments=arguments,
                dry_run=dry_run,
                active_permitted=active_permitted,
            )
            data = res.to_dict()
            if res.status == ExecutionStatus.BLOCKED.value:
                return self.fail(
                    message=res.stderr or f"Tool '{tool_name}' execution blocked by policy or authorization.",
                    error_code="EXECUTION_BLOCKED",
                    details=data,
                )
            if res.exit_code != 0 and res.status == ExecutionStatus.FAILED.value:
                return self.fail(
                    message=res.error_message or res.stderr or f"Tool '{tool_name}' execution failed.",
                    error_code="EXECUTION_FAILED",
                    details=data,
                )

            if res.status == ExecutionStatus.COMPLETED.value and res.exit_code == 0:
                try:
                    from nyx.core.recon import sync_exec_to_engagement
                    sync_exec_to_engagement(data, base_dir=self.base_dir)
                except Exception:
                    pass

            return self.ok(data=data, message=f"Executed tool '{tool_name}' successfully.")
        except Exception as ex:
            return self.fail(message=f"Execution service error: {ex}", error_code="INTERNAL_ERROR")

    def enqueue_tool(
        self,
        tool_name: str,
        target: str,
        arguments: list[str] | None = None,
        priority: int = 10,
        dry_run: bool = False,
    ) -> ServiceResult:
        """Enqueue a tool execution request."""
        try:
            req = ExecutionRequest(
                tool_name=tool_name,
                target=target,
                arguments=arguments or [],
                dry_run=dry_run,
            )
            exec_id = self.queue.enqueue(req, priority=priority)
            return self.ok(data={"execution_id": exec_id, "request": req.to_dict()}, message=f"Enqueued '{tool_name}' for target '{target}'.")
        except Exception as ex:
            return self.fail(message=f"Enqueue error: {ex}", error_code="QUEUE_ERROR")

    def run_queue(self) -> ServiceResult:
        """Process all queued execution items."""
        try:
            results = self.queue.execute_all(self.engine)
            res_dicts = [r.to_dict() for r in results]
            return self.ok(data={"processed_count": len(results), "results": res_dicts}, message=f"Processed {len(results)} queued executions.")
        except Exception as ex:
            return self.fail(message=f"Queue execution error: {ex}", error_code="QUEUE_EXECUTION_ERROR")

    def get_status(self, execution_id: str) -> ServiceResult:
        """Get status and stored artifacts for an execution ID."""
        try:
            art_info = get_execution_artifacts(execution_id)
            if art_info.get("status") == "error":
                return self.fail(message=art_info.get("message", "Execution not found."), error_code="NOT_FOUND")
            return self.ok(data=art_info.get("artifacts", {}), message=f"Retrieved status for {execution_id}.")
        except Exception as ex:
            return self.fail(message=f"Error getting execution status: {ex}", error_code="STATUS_ERROR")

    def get_history(self, limit: int = 50) -> ServiceResult:
        """Retrieve execution history log entries."""
        try:
            d = _get_eng_dir(create=False, base_dir=self.base_dir)
            db_file = d / "database" / "executions.json"
            if not db_file.exists():
                return self.ok(data={"history": [], "count": 0}, message="No execution history found.")

            history = json.loads(db_file.read_text(encoding="utf-8"))
            if isinstance(history, list):
                sliced = history[-limit:] if limit > 0 else history
                return self.ok(data={"history": sliced, "count": len(sliced), "total": len(history)})
            return self.ok(data={"history": [], "count": 0})
        except Exception as ex:
            return self.fail(message=f"Error reading execution history: {ex}", error_code="HISTORY_ERROR")

    def cancel_execution(self, execution_id: str) -> ServiceResult:
        """Cancel or mark an execution as CANCELLED."""
        try:
            # Check if in queue
            items = self.queue.list_queue()
            modified = False
            for it in items:
                req_data = it.get("request", {})
                if req_data.get("execution_id") == execution_id:
                    it["status"] = ExecutionStatus.CANCELLED.value
                    modified = True
            if modified:
                self.queue._save_raw_queue(items)
                return self.ok(data={"execution_id": execution_id, "status": ExecutionStatus.CANCELLED.value}, message=f"Cancelled queued execution {execution_id}.")

            return self.ok(data={"execution_id": execution_id, "status": "UNKNOWN"}, message=f"Execution {execution_id} was not in pending queue.")
        except Exception as ex:
            return self.fail(message=f"Cancel error: {ex}", error_code="CANCEL_ERROR")
