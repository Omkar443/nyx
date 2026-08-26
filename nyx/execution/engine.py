"""
NYX Security Tool Orchestration Engine
Core execution engine for security tools, adapter loading, policy enforcement, output sanitization, and artifact storage.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.api.tools import load_tools_registry
from nyx.security.authorization import check_authorization, is_hostname_in_scope, get_engagement_scope, sanitize_canonical_evidence
from nyx.models.execution import ExecutionRequest, ExecutionResult, ExecutionStatus
from nyx.execution.command import build_command
from nyx.execution.policy import check_policy, extract_hostname
from nyx.execution.timeout import run_with_timeout
from nyx.execution.sandbox import prepare_isolated_env
from nyx.execution.adapters import get_adapter
from nyx.execution.artifacts import store_execution_artifacts


class ExecutionEngine:
    """Production-grade Security Tool Orchestration Engine."""

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir

    def log_execution_to_db(self, result: ExecutionResult) -> None:
        """Persist execution log entry to .engagement/database/executions.json."""
        d = _get_eng_dir(create=True, base_dir=self.base_dir)
        db_dir = d / "database"
        db_dir.mkdir(parents=True, exist_ok=True)
        db_file = db_dir / "executions.json"

        existing = []
        if db_file.exists():
            try:
                existing = json.loads(db_file.read_text(encoding="utf-8"))
            except Exception:
                existing = []

        existing.append(result.to_dict())
        db_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    def execute_request(self, request: ExecutionRequest) -> ExecutionResult:
        """Execute a tool request using the engine pipeline."""
        return self.execute(
            tool_name=request.tool_name,
            target=request.target,
            arguments=request.arguments,
            dry_run=request.dry_run,
            active_permitted=request.active_permitted,
            execution_id=request.execution_id,
        )

    def execute(
        self,
        tool_name: str,
        target: str,
        arguments: list[str] | None = None,
        dry_run: bool = False,
        active_permitted: bool = False,
        timeout: int | None = None,
        execution_id: str | None = None,
    ) -> ExecutionResult:
        exec_id = execution_id or f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        start_time = datetime.now().isoformat()
        clean_target = extract_hostname(target)
        args_list = arguments or []

        # 1. Tool Registry Lookup
        tools_reg = load_tools_registry().get("tools", {})
        tool_entry = tools_reg.get(tool_name.lower().strip(), {})
        exec_class = tool_entry.get("execution_class", "SAFE_ACTIVE")
        tool_timeout = timeout or tool_entry.get("timeout", 60)
        adapter_path = tool_entry.get("adapter", "")

        # 2. Authorization Security Gate
        auth_req = tool_entry.get("required_authorization", True)
        if isinstance(tool_entry.get("authorization"), dict):
            auth_req = tool_entry.get("authorization", {}).get("required", auth_req)

        if auth_req:
            auth_ok, auth_msg = check_authorization()
            if not auth_ok:
                end_time = datetime.now().isoformat()
                res = ExecutionResult(
                    execution_id=exec_id,
                    tool_name=tool_name,
                    target=clean_target,
                    status=ExecutionStatus.BLOCKED.value,
                    exit_code=1,
                    stdout="",
                    stderr=f"[SECURITY BLOCKED] {auth_msg}",
                    started_at=start_time,
                    completed_at=end_time,
                    timeout=tool_timeout,
                    authorized=False,
                    scope_status="UNAUTHORIZED",
                    sanitized=True,
                    execution_class=exec_class,
                    dry_run=dry_run,
                    error_message=f"Authorization blocked: {auth_msg}",
                )
                self.log_execution_to_db(res)
                store_execution_artifacts(res)
                return res

            # Scope Boundary Gate
            scope_list = get_engagement_scope()
            if scope_list and not is_hostname_in_scope(clean_target, scope_list):
                end_time = datetime.now().isoformat()
                res = ExecutionResult(
                    execution_id=exec_id,
                    tool_name=tool_name,
                    target=clean_target,
                    status=ExecutionStatus.BLOCKED.value,
                    exit_code=1,
                    stdout="",
                    stderr=f"[SCOPE BLOCKED] Target '{clean_target}' is outside engagement scope boundaries.",
                    started_at=start_time,
                    completed_at=end_time,
                    timeout=tool_timeout,
                    authorized=False,
                    scope_status="OUT_OF_SCOPE",
                    sanitized=True,
                    execution_class=exec_class,
                    dry_run=dry_run,
                    error_message=f"Out of scope target: {clean_target}",
                )
                self.log_execution_to_db(res)
                store_execution_artifacts(res)
                return res

        # 3. Policy & Execution Class Verification
        policy_ok, pol_msg, scope_status = check_policy(
            tool_name, clean_target, execution_class=exec_class, active_permitted=active_permitted, dry_run=dry_run
        )
        if not policy_ok:
            end_time = datetime.now().isoformat()
            res = ExecutionResult(
                execution_id=exec_id,
                tool_name=tool_name,
                target=clean_target,
                status=ExecutionStatus.BLOCKED.value,
                exit_code=1,
                stdout="",
                stderr=pol_msg,
                started_at=start_time,
                completed_at=end_time,
                timeout=tool_timeout,
                authorized=False,
                scope_status=scope_status,
                sanitized=True,
                execution_class=exec_class,
                dry_run=dry_run,
                error_message=pol_msg,
            )
            self.log_execution_to_db(res)
            store_execution_artifacts(res)
            return res

        # 4. Adapter Resolution & Command Validation
        adapter = get_adapter(tool_name, adapter_path=adapter_path)
        if adapter:
            valid_input, err_msg = adapter.validate(target, args_list)
            if not valid_input:
                end_time = datetime.now().isoformat()
                res = ExecutionResult(
                    execution_id=exec_id,
                    tool_name=tool_name,
                    target=clean_target,
                    status=ExecutionStatus.FAILED.value,
                    exit_code=1,
                    stdout="",
                    stderr=f"[ADAPTER ERROR] {err_msg}",
                    started_at=start_time,
                    completed_at=end_time,
                    timeout=tool_timeout,
                    authorized=True,
                    scope_status=scope_status,
                    sanitized=True,
                    execution_class=exec_class,
                    dry_run=dry_run,
                    error_message=err_msg,
                )
                self.log_execution_to_db(res)
                store_execution_artifacts(res)
                return res

            cmd_list = adapter.build_command(target, args_list)
        else:
            valid_cmd, cmd_err, cmd_list = build_command(tool_name, target, args_list)
            if not valid_cmd:
                end_time = datetime.now().isoformat()
                res = ExecutionResult(
                    execution_id=exec_id,
                    tool_name=tool_name,
                    target=clean_target,
                    status=ExecutionStatus.FAILED.value,
                    exit_code=1,
                    stdout="",
                    stderr=cmd_err,
                    started_at=start_time,
                    completed_at=end_time,
                    command=cmd_list or [tool_name, clean_target],
                    timeout=tool_timeout,
                    authorized=False,
                    scope_status="INVALID_COMMAND",
                    sanitized=True,
                    execution_class=exec_class,
                    dry_run=dry_run,
                    error_message=cmd_err,
                )
                self.log_execution_to_db(res)
                store_execution_artifacts(res)
                return res

        # 5. Dry-Run Handling
        if dry_run or (exec_class == "ACTIVE" and not active_permitted):
            end_time = datetime.now().isoformat()
            dry_msg = (
                f"[DRY-RUN] Tool '{tool_name}' command constructed successfully. "
                f"Execution class: {exec_class}. Scope: {scope_status}. Authorized: True."
            )
            parsed_meta = {"dry_run": True, "command": cmd_list}
            if adapter:
                parsed_meta["adapter"] = adapter.__class__.__name__

            res = ExecutionResult(
                execution_id=exec_id,
                tool_name=tool_name,
                command=cmd_list,
                target=clean_target,
                status=ExecutionStatus.COMPLETED.value,
                started_at=start_time,
                completed_at=end_time,
                exit_code=0,
                stdout=dry_msg,
                stderr="",
                metadata=parsed_meta,
                timeout=tool_timeout,
                authorized=True,
                scope_status=scope_status,
                sanitized=True,
                execution_class=exec_class,
                dry_run=True,
            )
            self.log_execution_to_db(res)
            artifacts_map = store_execution_artifacts(res, parsed_data=parsed_meta)
            res.artifacts = artifacts_map
            return res

        # 6. Controlled Process Execution
        env = prepare_isolated_env()
        exit_code, stdout, stderr, timed_out = run_with_timeout(cmd_list, timeout_sec=tool_timeout, env=env)
        end_time = datetime.now().isoformat()

        # 7. Output Sanitization
        san_out = str(sanitize_canonical_evidence(stdout or "").content)
        san_err = str(sanitize_canonical_evidence(stderr or "").content)

        # 8. Result Parsing via Adapter if available
        parsed_data = {}
        if adapter:
            try:
                parsed_data = adapter.parse_result(san_out, san_err)
            except Exception as ex:
                parsed_data = {"adapter_error": str(ex)}

        status = ExecutionStatus.COMPLETED.value if exit_code == 0 else ExecutionStatus.FAILED.value
        err_msg = san_err if exit_code != 0 else None
        if timed_out:
            status = ExecutionStatus.FAILED.value
            err_msg = f"Execution timed out after {tool_timeout} seconds."

        res = ExecutionResult(
            execution_id=exec_id,
            tool_name=tool_name,
            command=cmd_list,
            target=clean_target,
            status=status,
            started_at=start_time,
            completed_at=end_time,
            exit_code=exit_code,
            stdout=san_out,
            stderr=san_err,
            metadata=parsed_data,
            timeout=tool_timeout,
            authorized=True,
            scope_status=scope_status,
            sanitized=True,
            execution_class=exec_class,
            dry_run=False,
            error_message=err_msg,
        )

        self.log_execution_to_db(res)
        artifacts_map = store_execution_artifacts(res, parsed_data=parsed_data)
        res.artifacts = artifacts_map
        return res