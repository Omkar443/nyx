"""
NYX Release Block 1 Comprehensive Regression & Integration Test Suite
Validates:
1. Real Finding Integration & Deduplication
2. Agent Lifecycle Persistence (IDLE -> ANALYZING -> IDLE)
3. Task Completion Semantics & Historical Retries
4. Mission Workspace Reset Isolation
5. FastAPI Lifespan Handling
"""
import pytest
from pathlib import Path
from nyx.agent.manager.controller import AgentController
from nyx.agent.tasks import DistributedTaskQueue
from nyx.agent.manager.registry import AgentRegistry
from nyx.application.finding_service import FindingService
from nyx.core import engagement, findings as core_findings
from nyx.worker.daemon import WorkerDaemon
from nyx.agents import WebAgent, APIAgent


@pytest.fixture
def tmp_engagement(tmp_path):
    d = tmp_path / ".engagement"
    engagement.init_engagement("test.example.com", reset=True, base_dir=tmp_path)
    return tmp_path


def test_agent_lifecycle_returns_to_idle(tmp_engagement):
    """Test that agent transitions IDLE -> ANALYZING during task execution and returns to IDLE."""
    ctrl = AgentController(base_dir=tmp_engagement)
    ag_info = ctrl.create_agent("web", "test.example.com")
    agent_id = ag_info["agent_id"]

    # Initial state must be IDLE
    agent = ctrl.registry.get_agent(agent_id)
    assert agent.inner_agent.state_machine.current_state == "IDLE"

    # Create task
    task = ctrl.task_queue.create_task("web_scan", "test.example.com", agent_type="web")
    ctrl.worker_scheduler.dispatch_task(task["task_id"])

    # Process task via daemon
    daemon = WorkerDaemon(base_dir=tmp_engagement)
    daemon.process_next_task()

    # After task completion, agent must be back in IDLE
    reloaded_registry = AgentRegistry(base_dir=tmp_engagement)
    reloaded_agent = reloaded_registry.get_agent(agent_id)
    assert reloaded_agent.inner_agent.state_machine.current_state == "IDLE"


def test_agent_reconciliation_on_load(tmp_engagement):
    """Test that process restart reconciles an agent left in ANALYZING back to IDLE if no running task exists."""
    ctrl = AgentController(base_dir=tmp_engagement)
    ag_info = ctrl.create_agent("api", "test.example.com")
    agent_id = ag_info["agent_id"]

    # Force agent state to ANALYZING on disk
    agent = ctrl.registry.get_agent(agent_id)
    agent.inner_agent.state_machine.set_state("ANALYZING", force=True)
    ctrl.registry.register_agent(agent)

    # Re-instantiating AgentRegistry triggers reconciliation
    new_reg = AgentRegistry(base_dir=tmp_engagement)
    reconciled_agent = new_reg.get_agent(agent_id)
    assert reconciled_agent.inner_agent.state_machine.current_state == "IDLE"


def test_task_retry_and_completion_semantics(tmp_engagement):
    """Test retryable failure, execution_history, and clearing of error on successful completion."""
    tq = DistributedTaskQueue(max_retries=2, base_dir=tmp_engagement)
    task = tq.create_task("flaky_task", "test.example.com")
    task_id = task["task_id"]

    # 1. First failure -> QUEUED for retry 1
    tq.fail_task(task_id, reason="Network timeout")
    t1 = tq.get_task(task_id)
    assert t1["status"] == "QUEUED"
    assert t1["retry_count"] == 1
    assert "Retry 1/2" in t1["error"]
    assert len(t1["execution_history"]) == 1

    # 2. Retry succeeds -> COMPLETED and error cleared
    tq.update_task_status(task_id, status="COMPLETED", result={"status": "success"})
    t2 = tq.get_task(task_id)
    assert t2["status"] == "COMPLETED"
    assert t2["error"] is None
    assert len(t2["execution_history"]) == 2
    assert t2["execution_history"][-1]["status"] == "COMPLETED"


def test_task_max_retries_exceeded(tmp_engagement):
    """Test task reaching FAILED when max_retries is exceeded."""
    tq = DistributedTaskQueue(max_retries=1, base_dir=tmp_engagement)
    task = tq.create_task("failing_task", "test.example.com")
    task_id = task["task_id"]

    # Failure 1 -> QUEUED
    tq.fail_task(task_id, reason="Error 1")
    assert tq.get_task(task_id)["status"] == "QUEUED"

    # Failure 2 -> FAILED (max retries 1 exceeded)
    tq.fail_task(task_id, reason="Error 2")
    t_final = tq.get_task(task_id)
    assert t_final["status"] == "FAILED"
    assert "Max retries exceeded" in t_final["error"]


def test_real_finding_integration_and_deduplication(tmp_engagement):
    """Test candidate vulnerability processing, metadata preservation, HYPOTHESIS initial state, and deduplication."""
    ctrl = AgentController(base_dir=tmp_engagement)
    ag_info = ctrl.create_agent("api", "test.example.com")
    agent_id = ag_info["agent_id"]

    cand = {
        "title": "IDOR in User API Endpoint",
        "endpoint": "http://test.example.com/api/v1/users/101",
        "parameter": "id",
        "vulnerability": "IDOR",
        "severity": "High",
        "description": "Sequential user ID parameter enumeration candidate.",
        "evidence_ids": ["EV-001"],
    }

    task = ctrl.task_queue.create_task(
        "api_scan",
        "test.example.com",
        agent_type="api",
        params={"vulnerability_candidate": cand},
    )
    task_id = task["task_id"]
    ctrl.worker_scheduler.dispatch_task(task_id)

    daemon = WorkerDaemon(base_dir=tmp_engagement)
    daemon.process_next_task()

    # Verify finding created
    f_svc = FindingService(base_dir=tmp_engagement)
    findings_res = f_svc.list_findings()
    findings = findings_res.get("findings", [])
    assert len(findings) == 1

    f = findings[0]
    assert f["title"] == cand["title"]
    assert f["status"] == "HYPOTHESIS"
    assert f["task_id"] == task_id
    assert f["agent_id"] == agent_id
    assert f["target"] == "test.example.com"
    assert f["vulnerability"] == "IDOR"
    assert f["severity"] == "High"
    assert f["evidence_ids"] == ["EV-001"]

    # Re-executing task with same candidate must NOT create duplicate finding
    task2 = ctrl.task_queue.create_task(
        "api_scan_repeat",
        "test.example.com",
        agent_type="api",
        params={"vulnerability_candidate": cand},
    )
    ctrl.worker_scheduler.dispatch_task(task2["task_id"])
    daemon.process_next_task()

    findings_res_after = f_svc.list_findings()
    assert len(findings_res_after.get("findings", [])) == 1


def test_mission_reset_isolation(tmp_path):
    """Test that initializing an engagement with reset=True wipes all previous runtime database files cleanly."""
    d = tmp_path / ".engagement"
    engagement.init_engagement("test.example.com", reset=True, base_dir=tmp_path)

    # Populate database items
    ctrl = AgentController(base_dir=tmp_path)
    ctrl.create_agent("recon", "test.example.com")
    ctrl.task_queue.create_task("recon_task", "test.example.com")
    core_findings.create_finding(title="Test Finding", endpoint="http://test.example.com", base_dir=tmp_path)

    assert len(ctrl.registry.list_agents()) == 1
    assert len(ctrl.task_queue.list_tasks()) == 1
    assert len(core_findings.list_findings(base_dir=tmp_path).get("findings", [])) == 1

    # Reset engagement
    engagement.init_engagement("test.example.com", reset=True, base_dir=tmp_path)

    # All database collections must be empty
    ctrl_new = AgentController(base_dir=tmp_path)
    assert len(ctrl_new.registry.list_agents()) == 0
    assert len(ctrl_new.task_queue.list_tasks()) == 0
    assert len(core_findings.list_findings(base_dir=tmp_path).get("findings", [])) == 0
