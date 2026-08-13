"""
NYX Worker Application Service
Facade managing remote worker node registration, health tracking, task dispatching, and evidence synchronization.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.application.base import BaseService, ServiceResult
from nyx.agent.manager.controller import AgentController
from nyx.distributed.evidence_sync import EvidenceSync


class WorkerService(BaseService):
    """Service facade for distributed worker node platform operations."""

    def __init__(self, provider_name: Optional[str] = None):
        super().__init__()
        self.controller = AgentController(provider_name=provider_name)
        self.evidence_sync = EvidenceSync()

    def register_worker(self, hostname: str, agents_supported: Optional[List[str]] = None) -> ServiceResult:
        res = self.controller.register_worker(hostname=hostname, agents_supported=agents_supported)
        return self.ok(data=res, message=f"Registered worker node '{res.get('worker_id')}' ({hostname}).")

    def list_workers(self, status: Optional[str] = None, agent_type: Optional[str] = None) -> ServiceResult:
        workers = self.controller.list_workers(status=status, agent_type=agent_type)
        return self.ok(data={"count": len(workers), "workers": workers}, message=f"Retrieved {len(workers)} worker nodes.")

    def remove_worker(self, worker_id: str) -> ServiceResult:
        ok = self.controller.remove_worker(worker_id)
        if not ok:
            return self.fail(message=f"Worker '{worker_id}' not found.", error_code="WORKER_NOT_FOUND")
        return self.ok(data={"worker_id": worker_id, "removed": True}, message=f"Removed worker node '{worker_id}'.")

    def dispatch_remote_task(self, task_id: str) -> ServiceResult:
        res = self.controller.worker_scheduler.dispatch_task(task_id)
        if not res.get("success"):
            return self.fail(message=res.get("error", "Dispatch failed."), error_code="DISPATCH_FAILED")
        return self.ok(data=res, message=f"Dispatched task '{task_id}' via mode '{res.get('execution_mode')}'.")

    def sync_worker_evidence(
        self,
        finding_id: str,
        filename: str,
        content_bytes: bytes,
        expected_sha256: str,
        worker_id: str = "WORKER-REMOTE",
    ) -> ServiceResult:
        ok, msg, data = self.evidence_sync.sync_remote_evidence(
            finding_id=finding_id,
            filename=filename,
            content_bytes=content_bytes,
            expected_sha256=expected_sha256,
            worker_id=worker_id,
        )
        if not ok:
            return self.fail(message=msg, error_code="EVIDENCE_SYNC_FAILED")
        return self.ok(data=data, message=msg)

    def get_worker_status(self) -> ServiceResult:
        workers = self.controller.list_workers()
        online_count = sum(1 for w in workers if w.get("status") == "ONLINE")
        return self.ok(
            data={"total_workers": len(workers), "online_workers": online_count, "workers": workers},
            message="Retrieved worker fleet status.",
        )
