"""
Regression tests for NYX Multi-Agent Mission Orchestration Integration.
"""
from __future__ import annotations

from pathlib import Path
from nyx.api.mission import init_mission, run_mission
from nyx.agent.manager.registry import AgentRegistry
from nyx.agent.tasks import DistributedTaskQueue
from nyx.application.fleet_service import FleetService
from nyx.application.worker_service import WorkerService


def test_mission_run_orchestration(tmp_path: Path, monkeypatch):
    target = "test.example.com"

    # Set working directory to tmp_path
    monkeypatch.chdir(tmp_path)

    # Mock authorization check
    from nyx.security import authorization
    monkeypatch.setattr(authorization, "check_authorization", lambda t: (True, "Authorized"))

    # Mock recon run
    from nyx.core import recon
    monkeypatch.setattr(recon, "run", lambda t: {"status": "success"})

    # 1. Initialize mission
    init_res = init_mission(target)
    assert init_res == 0

    # 2. Execute mission run
    run_res = run_mission(target)
    assert run_res == 0

    # 3. Test 1: Mission run creates agents (recon, technology, web, api, validation, reporting)
    agent_reg1 = AgentRegistry()
    agents = agent_reg1.list_agents()
    assert len(agents) >= 6
    agent_types = {a["agent_type"] for a in agents}
    assert "recon" in agent_types
    assert "technology" in agent_types
    assert "web" in agent_types
    assert "api" in agent_types
    assert "validation" in agent_types
    assert "reporting" in agent_types

    # 4. Test 2: Mission run creates tasks
    task_q1 = DistributedTaskQueue()
    tasks = task_q1.list_tasks()
    assert len(tasks) >= 6
    task_types = {t["task_type"] for t in tasks}
    assert "recon_passive" in task_types
    assert "technology_fingerprint" in task_types
    assert "endpoint_discovery" in task_types
    assert "attack_surface_mapping" in task_types
    assert "vulnerability_validation" in task_types
    assert "report_generation" in task_types

    # 5. Test 3 & 4: Tasks are dispatched and assigned to local agents (mode LOCAL)
    for t in tasks:
        assert t["execution_mode"] == "LOCAL"
        assert t["assigned_agent_id"] is not None

    # 6. Test 5: Completed tasks store results
    for t in tasks:
        assert t["status"] == "COMPLETED"
        assert t["result"] is not None

    # 7. Test 6: CLI restart (new registry/queue instances) preserves mission state
    agent_reg2 = AgentRegistry()
    task_q2 = DistributedTaskQueue()

    assert len(agent_reg2.list_agents()) == len(agents)
    assert len(task_q2.list_tasks()) == len(tasks)


def test_mission_run_target_mismatch_error_message(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    # Mock authorization check
    from nyx.security import authorization
    monkeypatch.setattr(authorization, "check_authorization", lambda t: (True, "Authorized"))

    # Initialize for target_a
    res_init = init_mission("target_a.com")
    assert res_init == 0

    # Attempt to run mission for different target_b without reset
    res_run = run_mission("target_b.com")
    assert res_run == 1

    captured = capsys.readouterr()
    assert "✗ Engagement Initialization Failed: Existing engagement workspace found for target 'target_a.com'" in captured.out
    assert "Cannot re-initialize for 'target_b.com' without explicit reset/force flag" in captured.out
