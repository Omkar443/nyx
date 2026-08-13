"""
NYX Execution Queue System
Manages sequential tool execution requests, priorities, and queued mission phases.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.models.execution import ExecutionRequest, ExecutionResult, ExecutionStatus


@dataclass
class QueueItem:
    request: ExecutionRequest
    priority: int = 10  # Lower number = higher priority
    status: str = ExecutionStatus.PENDING.value
    enqueued_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "priority": self.priority,
            "status": self.status,
            "enqueued_at": self.enqueued_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QueueItem:
        req_data = data.get("request") or data
        return cls(
            request=ExecutionRequest.from_dict(req_data),
            priority=int(data.get("priority", 10)),
            status=data.get("status") or ExecutionStatus.PENDING.value,
            enqueued_at=data.get("enqueued_at") or datetime.now().isoformat(),
        )


class ExecutionQueue:
    """Queue system for managing security tool execution pipelines."""

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir

    def _get_queue_file(self, create: bool = True) -> Path:
        d = _get_eng_dir(create=create, base_dir=self.base_dir)
        db_dir = d / "database"
        if create:
            db_dir.mkdir(parents=True, exist_ok=True)
        return db_dir / "queue.json"

    def _load_raw_queue(self) -> list[dict[str, Any]]:
        q_file = self._get_queue_file(create=False)
        if not q_file.exists():
            return []
        try:
            return json.loads(q_file.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save_raw_queue(self, items: list[dict[str, Any]]) -> None:
        q_file = self._get_queue_file(create=True)
        q_file.write_text(json.dumps(items, indent=2), encoding="utf-8")

    def enqueue(self, request: ExecutionRequest, priority: int = 10) -> str:
        """Enqueue an execution request."""
        item = QueueItem(request=request, priority=priority)
        items = self._load_raw_queue()
        items.append(item.to_dict())

        # Sort by priority ascending (1 = high priority), then enqueued_at
        items.sort(key=lambda x: (x.get("priority", 10), x.get("enqueued_at", "")))
        self._save_raw_queue(items)
        return request.execution_id

    def pop_next(self) -> ExecutionRequest | None:
        """Pop the next PENDING execution request from the queue."""
        items = self._load_raw_queue()
        for idx, it in enumerate(items):
            if it.get("status") == ExecutionStatus.PENDING.value:
                it["status"] = ExecutionStatus.RUNNING.value
                req = ExecutionRequest.from_dict(it.get("request", {}))
                items.pop(idx)
                self._save_raw_queue(items)
                return req
        return None

    def list_queue(self) -> list[dict[str, Any]]:
        """List all current queued execution items."""
        return self._load_raw_queue()

    def clear(self) -> None:
        """Clear all items in the queue."""
        self._save_raw_queue([])

    def execute_all(self, engine: Any) -> list[ExecutionResult]:
        """Process all queued requests sequentially through the given execution engine."""
        results = []
        while True:
            req = self.pop_next()
            if not req:
                break
            res = engine.execute_request(req)
            results.append(res)
        return results
