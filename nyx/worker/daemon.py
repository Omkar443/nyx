"""
NYX Worker Runtime Daemon
Consumes queued tasks from DistributedTaskQueue, dispatches via WorkerScheduler,
executes workloads through WorkerExecutor, updates persistent task state, and handles failure retries.
Supports local in-process execution and HTTP remote worker execution mode.
"""
from __future__ import annotations

import asyncio
import json
import platform
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from nyx.worker.executor import WorkerExecutor
from nyx.worker.heartbeat import WorkerHeartbeat
from nyx.worker.node import WorkerNode


def _http_request(
    url: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    token: Optional[str] = None,
) -> tuple[int, Dict[str, Any]]:
    """Helper executing HTTP REST requests against NYX Controller API."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-API-Token"] = token
    data_bytes = json.dumps(payload).encode("utf-8") if payload else None
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode("utf-8", errors="replace")
            return r.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, json.loads(body) if body else {}
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


class WorkerDaemon:
    """Production runtime daemon for processing security research tasks."""

    def __init__(
        self,
        worker_id: Optional[str] = None,
        hostname: Optional[str] = None,
        base_dir: Optional[Path] = None,
        provider_name: Optional[str] = None,
        server_url: Optional[str] = None,
        api_token: Optional[str] = None,
    ):
        from nyx.agent.manager.controller import AgentController

        self.base_dir = base_dir
        self.worker_id = worker_id or f"WRK-DAEMON-{uuid.uuid4().hex[:6].upper()}"
        self.hostname = hostname or platform.node() or "localhost"
        self.server_url = server_url.rstrip("/") if server_url else None
        self.api_token = api_token
        self.controller = AgentController(provider_name=provider_name, base_dir=base_dir)
        self.executor = WorkerExecutor(base_dir=base_dir)
        self.heartbeat_monitor = WorkerHeartbeat()
        self._stopped = False

        self.node = WorkerNode(
            worker_id=self.worker_id,
            hostname=self.hostname,
            name=self.hostname,
        )

        if self.server_url:
            # Register over HTTP with remote controller
            url = f"{self.server_url}/api/v1/workers/register?hostname={self.hostname}"
            code, res = _http_request(url, method="POST", token=self.api_token)
            if code == 200 and isinstance(res, dict) and "data" in res:
                d = res["data"]
                if isinstance(d, dict) and "worker_id" in d and not worker_id:
                    self.worker_id = d["worker_id"]
                    self.node.worker_id = self.worker_id
        else:
            self.controller.worker_registry.register_worker(self.node)

    def stop(self) -> None:
        """Signal daemon to stop processing."""
        self._stopped = True

    def process_next_task(self) -> Optional[Dict[str, Any]]:
        """Find, dispatch, and execute the next available eligible task."""
        if self.server_url:
            return self._process_remote_http_task()

        # 1. Recover stale tasks that timed out
        self.controller.task_queue.recover_stale_tasks()

        # 2. Update worker liveness heartbeat
        self.heartbeat_monitor.send_heartbeat(self.node)

        # 3. Find pending task in CREATED or QUEUED status
        pending_tasks = self.controller.task_queue.list_tasks(status="CREATED")
        if not pending_tasks:
            pending_tasks = self.controller.task_queue.list_tasks(status="QUEUED")

        if not pending_tasks:
            # Check for RUNNING tasks assigned to this worker/agent that were not finished
            running_tasks = self.controller.task_queue.list_tasks(status="RUNNING")
            for r_task in running_tasks:
                if r_task.get("assigned_worker_id") == self.worker_id or r_task.get("execution_mode") == "LOCAL":
                    # Attempt to claim and execute
                    if self.controller.task_queue.claim_task(r_task["task_id"], self.worker_id):
                        return self._execute_claimed_task(r_task)
            return None

        # Pick highest priority task
        candidate_task = pending_tasks[0]
        task_id = candidate_task["task_id"]
        req_target = candidate_task.get("target", "")
        req_agent_type = candidate_task.get("agent_type", "recon")

        local_agents = self.controller.registry.list_agents(target=req_target, agent_type=req_agent_type)
        if not local_agents and req_target:
            self.controller.create_agent(req_agent_type, req_target)

        # Dispatch via WorkerScheduler
        dispatch_res = self.controller.worker_scheduler.dispatch_task(task_id)
        if not dispatch_res.get("success"):
            return None

        dispatched_task = self.controller.task_queue.get_task(task_id)
        if not dispatched_task:
            return None

        exec_mode = dispatched_task.get("execution_mode")
        assigned_worker_id = dispatched_task.get("assigned_worker_id")

        # Handle REMOTE tasks assigned to other remote workers: do not execute locally
        if exec_mode == "REMOTE" and assigned_worker_id != self.worker_id:
            self.controller.bus.publish(
                sender="WORKER_DAEMON",
                receiver=assigned_worker_id or "REMOTE",
                event_type="task_dispatched_remote",
                payload={"task_id": task_id, "assigned_worker_id": assigned_worker_id},
            )
            return dispatched_task

        # Attempt atomic claim
        claimed = self.controller.task_queue.claim_task(task_id, self.worker_id)
        if not claimed:
            return None

        return self._execute_claimed_task(dispatched_task)

    def _process_remote_http_task(self) -> Optional[Dict[str, Any]]:
        """Process tasks in remote worker mode over HTTP REST API."""
        # 1. Send heartbeat over HTTP
        hb_url = f"{self.server_url}/api/v1/workers/{self.worker_id}/heartbeat"
        _http_request(hb_url, method="POST", token=self.api_token)

        # 2. Poll tasks assigned to this worker over HTTP
        poll_url = f"{self.server_url}/api/v1/workers/{self.worker_id}/tasks/poll"
        code, res = _http_request(poll_url, method="GET", token=self.api_token)
        if code != 200 or not isinstance(res, dict):
            return None

        d = res.get("data", {}) if isinstance(res.get("data"), dict) else res
        tasks = d.get("tasks", [])
        if not tasks:
            return None

        task = tasks[0]
        task_id = task["task_id"]

        # 3. Claim task over HTTP
        claim_url = f"{self.server_url}/api/v1/workers/{self.worker_id}/tasks/{task_id}/claim"
        c_code, c_res = _http_request(claim_url, method="POST", token=self.api_token)
        if c_code != 200:
            return None

        # 4. Execute workload locally through WorkerExecutor on remote node
        self.node.update_status("BUSY")
        try:
            exec_res = self.executor.execute_task(task)

            # 5. Submit structured execution result back over HTTP
            submit_url = f"{self.server_url}/api/v1/workers/{self.worker_id}/tasks/{task_id}/result"
            s_code, s_res = _http_request(submit_url, method="POST", payload=exec_res, token=self.api_token)
            return s_res.get("data") if s_code == 200 else exec_res
        finally:
            self.node.update_status("ONLINE")

    def _execute_claimed_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a claimed task through WorkerExecutor and handle state persistence & events."""
        task_id = task["task_id"]
        assigned_agent_id = task.get("assigned_agent_id")

        self.node.update_status("BUSY")
        self.controller.bus.publish(
            sender="WORKER_DAEMON",
            receiver=self.worker_id,
            event_type="task_claimed",
            payload={"task_id": task_id, "worker_id": self.worker_id},
        )

        # Update assigned agent state machine to RUNNING / ANALYZING
        agent_obj = None
        if assigned_agent_id:
            agent_obj = self.controller.registry.get_agent(assigned_agent_id)
            if agent_obj:
                try:
                    agent_obj.inner_agent.state_machine.set_state("ANALYZING", force=True)
                except Exception:
                    pass

        self.controller.bus.publish(
            sender="WORKER_DAEMON",
            receiver=assigned_agent_id or self.worker_id,
            event_type="task_started",
            payload={"task_id": task_id, "status": "RUNNING"},
        )

        try:
            exec_res = self.executor.execute_task(task)
            st = exec_res.get("status", "FAILED")

            if st == "COMPLETED":
                res_data = exec_res.get("result", {})
                self.controller.task_queue.update_task_status(
                    task_id=task_id,
                    status="COMPLETED",
                    result=res_data,
                )
                self.controller.bus.publish(
                    sender="WORKER_DAEMON",
                    receiver=assigned_agent_id or self.worker_id,
                    event_type="task_completed",
                    payload={"task_id": task_id, "result": res_data},
                )
            else:
                err_msg = exec_res.get("error", "Task execution failed.")
                ok, msg = self.controller.task_queue.fail_task(task_id, reason=err_msg)
                event_name = "task_requeued" if "queued for retry" in msg else "task_failed"
                self.controller.bus.publish(
                    sender="WORKER_DAEMON",
                    receiver=assigned_agent_id or self.worker_id,
                    event_type=event_name,
                    payload={"task_id": task_id, "error": err_msg},
                )
        except Exception as e:
            err_msg = str(e)
            ok, msg = self.controller.task_queue.fail_task(task_id, reason=err_msg)
            event_name = "task_requeued" if "queued for retry" in msg else "task_failed"
            self.controller.bus.publish(
                sender="WORKER_DAEMON",
                receiver=assigned_agent_id or self.worker_id,
                event_type=event_name,
                payload={"task_id": task_id, "error": err_msg},
            )
        finally:
            self.node.update_status("ONLINE")
            # Reset agent state back to IDLE so agent is not left stuck in RUNNING/ANALYZING
            if agent_obj:
                try:
                    agent_obj.inner_agent.state_machine.set_state("IDLE", force=True)
                    self.controller.registry.register_agent(agent_obj)
                except Exception:
                    pass

        return self.controller.task_queue.get_task(task_id) or task

    def process_all_available(self) -> int:
        processed = 0
        while not self._stopped:
            res = self.process_next_task()
            if not res:
                break
            processed += 1
        return processed

    def start_loop(self, poll_interval: float = 1.0, once: bool = False) -> int:
        """Start synchronous task execution loop."""
        if once:
            return self.process_all_available()

        processed_total = 0
        while not self._stopped:
            cnt = self.process_all_available()
            processed_total += cnt
            time.sleep(poll_interval)

        return processed_total

    async def start_async_loop(self, poll_interval: float = 1.0) -> None:
        """Start asynchronous task execution loop for FastAPI / web integration."""
        while not self._stopped:
            await asyncio.to_thread(self.process_all_available)
            await asyncio.sleep(poll_interval)
