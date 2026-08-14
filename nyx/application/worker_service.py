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

    def start_daemon(
        self,
        poll_interval: float = 1.0,
        once: bool = False,
        worker_id: Optional[str] = None,
        hostname: Optional[str] = None,
        server_url: Optional[str] = None,
        api_token: Optional[str] = None,
    ) -> ServiceResult:
        from nyx.worker.daemon import WorkerDaemon
        daemon = WorkerDaemon(
            worker_id=worker_id,
            hostname=hostname,
            provider_name=self.controller.provider_name,
            base_dir=self.controller.base_dir,
            server_url=server_url,
            api_token=api_token,
        )
        processed = daemon.start_loop(poll_interval=poll_interval, once=once)
        return self.ok(
            data={"worker_id": daemon.worker_id, "processed_tasks_count": processed, "once": once},
            message=f"Worker daemon processed {processed} task(s).",
        )

    def record_heartbeat(self, worker_id: str) -> ServiceResult:
        node = self.controller.worker_registry.get_worker(worker_id)
        if not node:
            return self.fail(message=f"Worker '{worker_id}' not found.", error_code="WORKER_NOT_FOUND")
        meta = self.controller.worker_registry.heartbeat_monitor.send_heartbeat(node)
        self.controller.worker_registry.register_worker(node)
        return self.ok(data=meta, message=f"Recorded heartbeat for worker '{worker_id}'.")

    def poll_remote_tasks(self, worker_id: str) -> ServiceResult:
        tasks = self.controller.task_queue.list_tasks(status="RUNNING")
        assigned = [
            t for t in tasks
            if t.get("execution_mode") == "REMOTE" and t.get("assigned_worker_id") == worker_id
        ]
        return self.ok(data={"count": len(assigned), "tasks": assigned}, message=f"Retrieved {len(assigned)} task(s) for worker '{worker_id}'.")

    def claim_remote_task(self, worker_id: str, task_id: str) -> ServiceResult:
        task = self.controller.task_queue.get_task(task_id)
        if not task:
            return self.fail(message=f"Task '{task_id}' not found.", error_code="TASK_NOT_FOUND")

        assigned_w = task.get("assigned_worker_id")
        if assigned_w and assigned_w != worker_id:
            return self.fail(
                message=f"Task '{task_id}' is assigned to worker '{assigned_w}', not '{worker_id}'.",
                error_code="TASK_OWNERSHIP_DENIED",
            )

        claimed = self.controller.task_queue.claim_task(task_id, worker_id)
        if not claimed:
            return self.fail(
                message=f"Task '{task_id}' already claimed by another worker.",
                error_code="TASK_ALREADY_CLAIMED",
            )

        self.controller.task_queue.update_task_status(
            task_id=task_id,
            status="RUNNING",
            assigned_worker_id=worker_id,
            execution_mode="REMOTE",
        )
        updated_task = self.controller.task_queue.get_task(task_id)
        return self.ok(data=updated_task, message=f"Worker '{worker_id}' claimed task '{task_id}'.")

    def submit_task_result(
        self,
        worker_id: str,
        task_id: str,
        status: str,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> ServiceResult:
        task = self.controller.task_queue.get_task(task_id)
        if not task:
            return self.fail(message=f"Task '{task_id}' not found.", error_code="TASK_NOT_FOUND")

        claimed_w = task.get("claimed_by") or task.get("assigned_worker_id")
        if claimed_w and claimed_w != worker_id:
            return self.fail(
                message=f"Task '{task_id}' was claimed by '{claimed_w}', submission from '{worker_id}' denied.",
                error_code="TASK_OWNERSHIP_DENIED",
            )

        st = status.upper()
        if st == "COMPLETED":
            self.controller.task_queue.update_task_status(
                task_id=task_id,
                status="COMPLETED",
                result=result or {},
                assigned_worker_id=worker_id,
                execution_mode="REMOTE",
            )
            updated = self.controller.task_queue.get_task(task_id)
            return self.ok(data=updated, message=f"Task '{task_id}' completed by worker '{worker_id}'.")
        else:
            ok, msg = self.controller.task_queue.fail_task(task_id, reason=error or "Remote execution failed.")
            updated = self.controller.task_queue.get_task(task_id)
            return self.ok(data=updated, message=msg)
