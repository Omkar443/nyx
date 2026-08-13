"""
NYX Execution Domain Models
Canonical data types for execution requests, execution results, and execution lifecycle status.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ExecutionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    BLOCKED = "BLOCKED"


@dataclass
class ExecutionRequest:
    execution_id: str = field(default_factory=lambda: f"EXEC-{uuid.uuid4().hex[:8].upper()}")
    tool_name: str = ""
    target: str = ""
    arguments: list[str] = field(default_factory=list)
    authorization_scope: list[str] = field(default_factory=list)
    dry_run: bool = False
    active_permitted: bool = False
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "tool_name": self.tool_name,
            "target": self.target,
            "arguments": self.arguments,
            "authorization_scope": self.authorization_scope,
            "dry_run": self.dry_run,
            "active_permitted": self.active_permitted,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionRequest:
        return cls(
            execution_id=data.get("execution_id") or f"EXEC-{uuid.uuid4().hex[:8].upper()}",
            tool_name=data.get("tool_name") or data.get("tool") or "",
            target=data.get("target", ""),
            arguments=data.get("arguments") or data.get("args") or [],
            authorization_scope=data.get("authorization_scope") or [],
            dry_run=bool(data.get("dry_run", False)),
            active_permitted=bool(data.get("active_permitted", False)),
            created_at=data.get("created_at") or datetime.now().isoformat(),
        )


@dataclass
class ExecutionResult:
    execution_id: str
    tool_name: str
    target: str
    status: str = ExecutionStatus.COMPLETED.value
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    artifacts: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    command: list[str] = field(default_factory=list)
    timeout: int = 60
    authorized: bool = True
    scope_status: str = "IN_SCOPE"
    sanitized: bool = True
    execution_class: str = "SAFE_ACTIVE"
    evidence_id: str | None = None
    dry_run: bool = False
    error_message: str | None = None

    @property
    def tool(self) -> str:
        return self.tool_name

    @tool.setter
    def tool(self, val: str) -> None:
        self.tool_name = val

    @property
    def start_time(self) -> str:
        return self.started_at

    @start_time.setter
    def start_time(self, val: str) -> None:
        self.started_at = val

    @property
    def end_time(self) -> str:
        return self.completed_at

    @end_time.setter
    def end_time(self, val: str) -> None:
        self.completed_at = val

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "tool_name": self.tool_name,
            "tool": self.tool_name,
            "target": self.target,
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": self.started_at,
            "start_time": self.started_at,
            "completed_at": self.completed_at,
            "end_time": self.completed_at,
            "artifacts": self.artifacts,
            "metadata": self.metadata,
            "command": self.command,
            "timeout": self.timeout,
            "authorized": self.authorized,
            "scope_status": self.scope_status,
            "sanitized": self.sanitized,
            "execution_class": self.execution_class,
            "evidence_id": self.evidence_id,
            "dry_run": self.dry_run,
            "error_message": self.error_message,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionResult:
        return cls(
            execution_id=data.get("execution_id", ""),
            tool_name=data.get("tool_name") or data.get("tool") or "",
            target=data.get("target", ""),
            status=data.get("status") or ExecutionStatus.COMPLETED.value,
            exit_code=int(data.get("exit_code", 0)),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            started_at=data.get("started_at") or data.get("start_time") or datetime.now().isoformat(),
            completed_at=data.get("completed_at") or data.get("end_time") or datetime.now().isoformat(),
            artifacts=data.get("artifacts") or {},
            metadata=data.get("metadata") or {},
            command=data.get("command") or [],
            timeout=int(data.get("timeout", 60)),
            authorized=bool(data.get("authorized", True)),
            scope_status=data.get("scope_status", "IN_SCOPE"),
            sanitized=bool(data.get("sanitized", True)),
            execution_class=data.get("execution_class", "SAFE_ACTIVE"),
            evidence_id=data.get("evidence_id"),
            dry_run=bool(data.get("dry_run", False)),
            error_message=data.get("error_message"),
        )
