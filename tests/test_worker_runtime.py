"""
NYX Worker Runtime Integration & Verification Test Suite
Verifies end-to-end task queue processing, local execution, error handling/retries,
CLI commands, process boundaries, duplicate claim prevention, agent lifecycle, and web server integration.
"""
import pytest
from pathlib import Path
from nyx.agent.tasks import DistributedTaskQueue
from nyx.agent.manager.controller import AgentController
from nyx.worker.daemon import WorkerDaemon
from nyx.application.worker_service import WorkerService
from nyx.web.app import create_app
from nyx.core.engagement import init_engagement
from fastapi.testclient import TestClient


def test_1_local_execution(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_engagement("test.example.com", base_dir=tmp_path)

    q = DistributedTaskQueue(base_dir=tmp_path)
    task = q.create_task(
        task_type="recon_passive",
        target="test.example.com",
        agent_type="recon",
        priority=9,
    )
    assert task["status"] == "CREATED"

    daemon = WorkerDaemon(worker_id="WRK-TEST-1", base_dir=tmp_path)
    processed = daemon.process_all_available()
    assert processed >= 1

    # Verify task persisted as COMPLETED
    q_new = DistributedTaskQueue(base_dir=tmp_path)
    updated = q_new.get_task(task["task_id"])
    assert updated is not None
    assert updated["status"] == "COMPLETED"
    assert updated["assigned_agent_id"] is not None
    assert updated["result"] is not None
    assert "target" in updated["result"] or "assets" in updated["result"]


def test_2_failure_and_retries(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    q = DistributedTaskQueue(max_retries=2, base_dir=tmp_path)
    # Create task with un-authorized target format that causes security scope failure in WorkerExecutor
    task = q.create_task(
        task_type="invalid_task",
        target="unauthorized.out-of-scope-target.com",
        agent_type="recon",
        priority=8,
    )

    daemon = WorkerDaemon(worker_id="WRK-TEST-2", base_dir=tmp_path)
    
    # First attempt: failure -> queued for retry 1
    daemon.process_next_task()
    t1 = q.get_task(task["task_id"])
    assert t1["status"] in ["QUEUED", "FAILED"]
    assert t1["retry_count"] >= 1

    # Drain remaining retries
    daemon.process_all_available()
    t_final = q.get_task(task["task_id"])
    assert t_final["status"] == "FAILED"
    assert "Max retries exceeded" in t_final["error"] or "SECURITY" in t_final["error"] or "SCOPE" in t_final["error"]


def test_3_worker_cli_facade(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_engagement("test.example.com", base_dir=tmp_path)

    svc = WorkerService()
    svc.controller.base_dir = tmp_path
    svc.controller.task_queue.base_dir = tmp_path

    # Enqueue task
    svc.controller.task_queue.create_task(
        task_type="technology_fingerprint",
        target="test.example.com",
        agent_type="technology",
    )

    # Run daemon facade once
    res = svc.start_daemon(once=True)
    assert res.is_success
    assert res.data["processed_tasks_count"] >= 1


def test_4_process_boundary_persistence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_engagement("test.example.com", base_dir=tmp_path)

    # Process A: create task
    q1 = DistributedTaskQueue(base_dir=tmp_path)
    t = q1.create_task(task_type="endpoint_discovery", target="test.example.com", agent_type="web")
    tid = t["task_id"]

    # Process B: run worker runtime
    daemon = WorkerDaemon(worker_id="WRK-PROC-B", base_dir=tmp_path)
    daemon.process_all_available()

    # Process C: verify completed state
    q3 = DistributedTaskQueue(base_dir=tmp_path)
    final_t = q3.get_task(tid)
    assert final_t["status"] == "COMPLETED"
    assert final_t["result"] is not None


def test_5_duplicate_execution_protection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_engagement("test.example.com", base_dir=tmp_path)

    q = DistributedTaskQueue(base_dir=tmp_path)
    t = q.create_task(task_type="recon_passive", target="test.example.com", agent_type="recon")
    tid = t["task_id"]

    d1 = WorkerDaemon(worker_id="WRK-ALPHA", base_dir=tmp_path)
    d2 = WorkerDaemon(worker_id="WRK-BETA", base_dir=tmp_path)

    # Claim task via d1
    claimed = q.claim_task(tid, d1.worker_id)
    assert claimed is True

    # Try claim task via d2
    claimed_again = q.claim_task(tid, d2.worker_id)
    assert claimed_again is False


def test_6_agent_lifecycle_state_sync(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_engagement("test.example.com", base_dir=tmp_path)

    ctrl = AgentController(base_dir=tmp_path)
    ag = ctrl.create_agent("recon", "test.example.com")
    ag_id = ag["agent_id"]

    t = ctrl.task_queue.create_task(task_type="recon_passive", target="test.example.com", agent_type="recon")

    daemon = WorkerDaemon(worker_id="WRK-TEST-6", base_dir=tmp_path)
    daemon.process_all_available()

    # Agent should reset to DISCOVERY / IDLE rather than remaining stuck in RUNNING/ANALYZING
    agent_info = ctrl.registry.get_agent(ag_id)
    assert agent_info is not None
    assert agent_info.inner_agent.state_machine.current_state in ["IDLE", "COMPLETED"]


def test_7_web_server_integration(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_engagement("test.example.com", base_dir=tmp_path)

    app = create_app()
    with TestClient(app) as client:
        # Health check
        res = client.get("/health")
        assert res.status_code == 200

        # Create task via Queue
        q = DistributedTaskQueue(base_dir=tmp_path)
        t = q.create_task(task_type="attack_surface_mapping", target="test.example.com", agent_type="api")

        daemon = WorkerDaemon(worker_id="WRK-WEB-TEST", base_dir=tmp_path)
        daemon.process_all_available()

        updated = q.get_task(t["task_id"])
        assert updated["status"] == "COMPLETED"


def test_8_remote_http_worker_e2e_flow(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_engagement("test.example.com", base_dir=tmp_path)

    app = create_app()
    with TestClient(app) as client:
        # Get active API token from health endpoint
        h_res = client.get("/health").json()
        token = h_res["api_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Register worker node over HTTP
        reg_res = client.post("/api/v1/workers/register?hostname=remote-worker-node-1", headers=headers)
        assert reg_res.status_code == 200
        w_id = reg_res.json()["data"]["worker_id"]

        # 2. Create task assigned to REMOTE worker
        q = DistributedTaskQueue(base_dir=tmp_path)
        task = q.create_task(
            task_type="recon_passive",
            target="test.example.com",
            agent_type="recon",
            execution_mode="REMOTE",
        )
        tid = task["task_id"]
        q.update_task_status(tid, status="RUNNING", assigned_worker_id=w_id, execution_mode="REMOTE")

        # 3. Remote worker sends heartbeat over HTTP
        hb_res = client.post(f"/api/v1/workers/{w_id}/heartbeat", headers=headers)
        assert hb_res.status_code == 200

        # 4. Remote worker polls tasks over HTTP
        poll_res = client.get(f"/api/v1/workers/{w_id}/tasks/poll", headers=headers)
        assert poll_res.status_code == 200
        assigned_tasks = poll_res.json()["data"]["tasks"]
        assert len(assigned_tasks) >= 1
        assert assigned_tasks[0]["task_id"] == tid

        # 5. Remote worker claims task over HTTP
        claim_res = client.post(f"/api/v1/workers/{w_id}/tasks/{tid}/claim", headers=headers)
        assert claim_res.status_code == 200

        # 6. Remote worker executes workload & submits result over HTTP
        exec_payload = {
            "task_id": tid,
            "status": "COMPLETED",
            "result": {"remote_execution": True, "assets": ["test.example.com"]},
        }
        submit_res = client.post(f"/api/v1/workers/{w_id}/tasks/{tid}/result", json=exec_payload, headers=headers)
        assert submit_res.status_code == 200

        # 7. Verify persisted state
        final_task = q.get_task(tid)
        assert final_task["status"] == "COMPLETED"
        assert final_task["execution_mode"] == "REMOTE"
        assert final_task["assigned_worker_id"] == w_id
        assert final_task["result"]["remote_execution"] is True


def test_9_remote_worker_authorization_and_ownership_checks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_engagement("test.example.com", base_dir=tmp_path)

    app = create_app()
    with TestClient(app) as client:
        # 1. Unauthorized request without token
        unauth_res = client.post("/api/v1/workers/WRK-FAKE/heartbeat")
        assert unauth_res.status_code == 401

        # Authenticate
        token = client.get("/health").json()["api_token"]
        headers = {"Authorization": f"Bearer {token}"}

        reg_a = client.post("/api/v1/workers/register?hostname=node-a", headers=headers).json()
        reg_b = client.post("/api/v1/workers/register?hostname=node-b", headers=headers).json()
        w_a = reg_a["data"]["worker_id"]
        w_b = reg_b["data"]["worker_id"]

        q = DistributedTaskQueue(base_dir=tmp_path)
        task = q.create_task(task_type="recon_passive", target="test.example.com", execution_mode="REMOTE")
        tid = task["task_id"]
        q.update_task_status(tid, status="RUNNING", assigned_worker_id=w_a, execution_mode="REMOTE")

        # Worker B trying to claim Worker A's task -> FORBIDDEN (403)
        b_claim = client.post(f"/api/v1/workers/{w_b}/tasks/{tid}/claim", headers=headers)
        assert b_claim.status_code == 403

        # Worker A claims task
        a_claim = client.post(f"/api/v1/workers/{w_a}/tasks/{tid}/claim", headers=headers)
        assert a_claim.status_code == 200

        # Worker B trying to submit result for Worker A's task -> FORBIDDEN (403)
        b_submit = client.post(f"/api/v1/workers/{w_b}/tasks/{tid}/result", json={"status": "COMPLETED"}, headers=headers)
        assert b_submit.status_code == 403


def test_10_remote_tasks_never_executed_locally_by_controller_daemon(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    init_engagement("test.example.com", base_dir=tmp_path)

    q = DistributedTaskQueue(base_dir=tmp_path)
    task = q.create_task(
        task_type="recon_passive",
        target="test.example.com",
        agent_type="recon",
        execution_mode="REMOTE",
    )
    tid = task["task_id"]
    q.update_task_status(tid, status="RUNNING", assigned_worker_id="WRK-REMOTE-999", execution_mode="REMOTE")

    # Local daemon runs
    daemon = WorkerDaemon(worker_id="WRK-LOCAL-DAEMON", base_dir=tmp_path)
    daemon.process_all_available()

    # Verify task was NOT executed locally
    current_t = q.get_task(tid)
    assert current_t["status"] == "RUNNING"
    assert current_t["assigned_worker_id"] == "WRK-REMOTE-999"
    assert current_t["claimed_by"] != "WRK-LOCAL-DAEMON"

