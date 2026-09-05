"""
Regression test suite for NYX 5 Confirmed Architectural Fixes.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from nyx.application.analysis_service import AnalysisService
from nyx.application.continuous_service import ContinuousService
from nyx.intelligence.tracking import AssetTracker
from nyx.validation.rules import get_rule
from nyx.core.knowledge import search_knowledge
from nyx.infrastructure.filesystem import _get_eng_dir


def test_analyze_context_output():
    service = AnalysisService()
    ctx = service.get_decision_context(target="example.com")
    assert ctx["status"] == "success"
    assert "target" in ctx
    assert "endpoint" in ctx
    assert "technologies" in ctx
    assert "recommended_skills" in ctx
    assert "graph" in ctx


def test_analyze_surface_consistency(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "recon" / "example.com").mkdir(parents=True, exist_ok=True)
    manifest = {
        "target": "example.com",
        "endpoints": ["https://example.com/login", "https://example.com/api/user"]
    }
    (tmp_path / "recon" / "example.com" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    service = AnalysisService()
    res = service.rank_surface(target="example.com")
    assert res.get("status") in ("success", "ok")
    assert "rankings" in res
    assert isinstance(res["rankings"], list)


def test_asset_history_ingestion(tmp_path: Path):
    d = _get_eng_dir(base_dir=tmp_path, create=True)
    
    # Write mock engagement inventories
    eps = [{"url": "https://example.com/api/test", "method": "GET", "host": "example.com"}]
    techs = {"web": ["react", "node.js"]}
    (d / "endpoints.json").write_text(json.dumps(eps), encoding="utf-8")
    (d / "technologies.json").write_text(json.dumps(techs), encoding="utf-8")

    tracker = AssetTracker(base_dir=tmp_path)
    snapshot = tracker.record_current_state("example.com")

    graph_dict = snapshot.get("graph", {})
    assert len(graph_dict.get("endpoints", [])) == 1
    assert len(graph_dict.get("technologies", [])) == 2
    assert graph_dict["endpoints"][0]["path"] == "https://example.com/api/test"


def test_validation_rule_aliases():
    rule_xss = get_rule("xss")
    rule_xss_upper = get_rule("XSS")
    rule_reflected = get_rule("reflected_xss")
    rule_sqli = get_rule("sqli")
    rule_idor = get_rule("idor")
    rule_invalid = get_rule("xyz-invalid-e2e")

    assert rule_xss is not None
    assert rule_xss["type"] == "Reflected XSS"
    assert rule_xss_upper is not None
    assert rule_xss_upper["type"] == "Reflected XSS"
    assert rule_reflected is not None
    assert rule_reflected["type"] == "Reflected XSS"
    assert rule_sqli is not None
    assert rule_sqli["type"] == "SQL Injection"
    assert rule_idor is not None
    assert rule_idor["type"] == "IDOR"
    assert rule_invalid is None


def test_knowledge_search_relevance():
    res_idor = search_knowledge(keyword="idor")
    assert res_idor["primary_intent"] == "vulnerability"
    assert len(res_idor["matched_vulnerabilities"]) > 0

    res_graphql = search_knowledge(keyword="graphql")
    assert res_graphql["primary_intent"] == "technology"
    assert len(res_graphql["matched_technologies"]) > 0


def test_worker_persistence(tmp_path: Path):
    from nyx.agent.manager.worker_registry import WorkerRegistry
    from nyx.worker.node import WorkerNode

    reg1 = WorkerRegistry(base_dir=tmp_path)
    node = WorkerNode(hostname="test-worker-node", name="worker-node-1")
    w_id = reg1.register_worker(node)

    assert w_id == node.worker_id
    assert len(reg1.list_workers()) == 1

    # Instantiate separate registry process simulation reading from disk
    reg2 = WorkerRegistry(base_dir=tmp_path)
    workers2 = reg2.list_workers()
    assert len(workers2) == 1
    assert workers2[0]["worker_id"] == w_id
    assert workers2[0]["name"] == "worker-node-1"
    assert workers2[0]["status"] == "ONLINE"
    assert "auth_token" in workers2[0]

    # Test removal
    ok = reg2.remove_worker(w_id)
    assert ok is True
    assert len(reg2.list_workers()) == 0

    # Verify removal persisted
    reg3 = WorkerRegistry(base_dir=tmp_path)
    assert len(reg3.list_workers()) == 0


def test_agent_persistence(tmp_path: Path):
    from nyx.agent.manager.registry import AgentRegistry
    from nyx.agents.recon_agent import ReconAgent

    reg1 = AgentRegistry(base_dir=tmp_path)
    agent = ReconAgent(target="test.example.com")
    a_id = reg1.register_agent(agent)

    assert a_id == agent.agent_id
    assert len(reg1.list_agents()) == 1

    # Instantiate separate registry process simulation reading from disk
    reg2 = AgentRegistry(base_dir=tmp_path)
    agents2 = reg2.list_agents()
    assert len(agents2) == 1
    assert agents2[0]["agent_id"] == a_id
    assert agents2[0]["agent_type"] == "recon"
    assert agents2[0]["target"] == "test.example.com"
    assert "allowed_skills" in agents2[0]

    # Test unregister/stop
    ok = reg2.unregister_agent(a_id)
    assert ok is True
    assert len(reg2.list_agents()) == 0

    # Verify unregister persisted
    reg3 = AgentRegistry(base_dir=tmp_path)
    assert len(reg3.list_agents()) == 0


def test_task_persistence(tmp_path: Path):
    from nyx.agent.tasks import DistributedTaskQueue

    queue1 = DistributedTaskQueue(base_dir=tmp_path)
    t1 = queue1.create_task(
        task_type="recon_passive",
        target="test.example.com",
        agent_type="recon",
        priority=9,
    )
    t_id = t1["task_id"]

    assert t_id.startswith("TSK-")
    assert len(queue1.list_tasks()) == 1

    # Instantiate separate task queue process simulation reading from disk
    queue2 = DistributedTaskQueue(base_dir=tmp_path)
    tasks2 = queue2.list_tasks()
    assert len(tasks2) == 1
    assert tasks2[0]["task_id"] == t_id
    assert tasks2[0]["task_type"] == "recon_passive"
    assert tasks2[0]["priority"] == 9
    assert tasks2[0]["status"] == "CREATED"

    # Test update status
    ok, msg = queue2.update_task_status(t_id, status="RUNNING", assigned_worker_id="WRK-123456")
    assert ok is True

    # Verify update persisted across new queue instance
    queue3 = DistributedTaskQueue(base_dir=tmp_path)
    t3 = queue3.get_task(t_id)
    assert t3 is not None
    assert t3["status"] == "RUNNING"
    assert t3["assigned_worker_id"] == "WRK-123456"

    # Test clear/deletion
    queue3.clear()
    assert len(queue3.list_tasks()) == 0

    queue4 = DistributedTaskQueue(base_dir=tmp_path)
    assert len(queue4.list_tasks()) == 0


def test_cli_main_loads_dotenv(tmp_path: Path, monkeypatch):
    import os
    import sys
    from unittest.mock import patch
    from nyx_cli.cli import main

    test_env_file = tmp_path / ".env"
    test_env_file.write_text("NYX_TEST_ENV_VAR=auto_loaded_success\nNYX_EXISTING_VAR=from_env_file\n", encoding="utf-8")

    monkeypatch.setenv("NYX_EXISTING_VAR", "already_exported")
    if "NYX_TEST_ENV_VAR" in os.environ:
        monkeypatch.delenv("NYX_TEST_ENV_VAR", raising=False)

    with patch("nyx_cli.cli.REPO_ROOT", tmp_path), \
         patch.object(sys, "argv", ["nyx", "--help"]), \
         patch("sys.exit"):
        try:
            main()
        except SystemExit:
            pass

    assert os.environ.get("NYX_TEST_ENV_VAR") == "auto_loaded_success"
    # override=False ensures existing exported env var was not clobbered
    assert os.environ.get("NYX_EXISTING_VAR") == "already_exported"


def test_classify_url_stopwords_filter():
    from nyx.core.analysis import classify_url

    url = "https://server.vulnapp.id/mutillidae/documentation/how-to-access-Mutillidae-over-Virtual-Box-network.php"
    res = classify_url(url)
    assert res["status"] == "success"
    matches = res["matches"]

    # Pattern-based matches for .php and /documentation/ (document regex) are preserved
    assert "hunt-rce" in matches
    assert "hunt-aspnet" in matches

    # Generic word overlap false positives must be filtered out
    assert "vmware-vcenter-attack" not in matches
    assert "hunt-grpc" not in matches
    assert "hunt-k8s" not in matches


def test_classify_url_fintech_graphql():
    from nyx.core.analysis import classify_url

    url = "https://api.target.com/payment/graphql?mutation=transferFunds"
    res = classify_url(url)
    assert res["status"] == "success"
    matches = res["matches"]
    assert "hunt-fintech-graphql" in matches
    assert "hunt-graphql" in matches


def test_knowledge_search_expanded_capabilities():
    from nyx.core.knowledge import search_knowledge

    # 1. Technology search
    k8s_res = search_knowledge(technology="k8s")
    assert any(t["technology"]["name"] == "Kubernetes" for t in k8s_res["matched_technologies"])

    next_res = search_knowledge(technology="nextjs")
    assert any(t["technology"]["name"] == "Next.js" for t in next_res["matched_technologies"])

    # 2. Vulnerability search
    fintech_res = search_knowledge(keyword="transferFunds")
    assert any("GraphQL Financial" in v["vulnerability"]["name"] for v in fintech_res["matched_vulnerabilities"])

    cache_res = search_knowledge(keyword="cache deception")
    assert any("Cache Deception" in v["vulnerability"]["name"] for v in cache_res["matched_vulnerabilities"])


def test_cli_analyze_context_positional_target(capsys, monkeypatch):
    import sys
    from nyx_cli.cli import main, cmd_analyze
    import argparse

    # 1. Direct handler test with target
    args = argparse.Namespace(analyze_subcommand="context", target="testtarget.com", url=None)
    ret = cmd_analyze(args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "NYX Intelligence Decision Context — testtarget.com" in captured.out
    assert "Target Domain:    testtarget.com" in captured.out

    # 2. Handler test with target and custom url
    args_url = argparse.Namespace(analyze_subcommand="context", target="testtarget.com", url="https://testtarget.com/custom-auth")
    ret_url = cmd_analyze(args_url)
    assert ret_url == 0
    captured_url = capsys.readouterr()
    assert "Endpoint Scope:   https://testtarget.com/custom-auth" in captured_url.out

    # 3. CLI main() execution with positional target
    monkeypatch.setattr(sys, "argv", ["nyx", "analyze", "context", "targetsite.org"])
    ret_main = main()
    assert ret_main == 0
    captured_main = capsys.readouterr()
    assert "NYX Intelligence Decision Context — targetsite.org" in captured_main.out

    # 4. Analyze surface remains functional
    args_srf = argparse.Namespace(analyze_subcommand="surface", target="testtarget.com", manifest=None)
    ret_srf = cmd_analyze(args_srf)
    assert ret_srf in (0, 1)  # 0 or 1 depending on manifest presence


def test_target_switch_and_data_isolation(tmp_path: Path, monkeypatch):
    """Verify that switching target resets findings, endpoints, and evidence so new target is isolated."""
    from nyx.core import engagement as core_eng
    from nyx.core import findings as core_find
    from nyx.application.engagement_service import EngagementService
    from nyx.application.finding_service import FindingService
    from nyx.application.recon_service import ReconService

    monkeypatch.chdir(tmp_path)
    
    # 1. Initialize first target: 127.0.0.1:3000
    core_eng.init_engagement("127.0.0.1:3000", reset=True, force=True)
    core_find.create_finding(
        title="SQLi in 127.0.0.1",
        endpoint="http://127.0.0.1:3000/rest/user/login",
        vulnerability="SQL Injection",
        target="127.0.0.1:3000"
    )
    
    find_svc = FindingService()
    recon_svc = ReconService()
    eng_svc = EngagementService()

    f1 = find_svc.list_findings()
    assert len(f1.get("findings", [])) == 1

    # 2. Update target to tesla.com via update_settings
    res = eng_svc.update_settings(target="tesla.com", scope=["*.tesla.com", "tesla.com"])
    assert res["status"] == "success"
    assert res["target_changed"] is True

    # 3. Verify clean isolated state for tesla.com
    f2 = find_svc.list_findings()
    assert len(f2.get("findings", [])) == 0

    eps2 = recon_svc.get_endpoints()
    assert len(eps2.get("endpoints", [])) == 0

    techs2 = recon_svc.get_technologies()
    assert techs2.get("count", 0) == 0

    # 4. Create finding on tesla.com and verify isolation
    core_find.create_finding(
        title="Subdomain Takeover on tesla.com",
        endpoint="https://sub.tesla.com",
        vulnerability="Subdomain Takeover",
        target="tesla.com"
    )
    f3 = find_svc.list_findings()
    assert len(f3.get("findings", [])) == 1
    assert f3.get("findings", [])[0]["target"] == "tesla.com"


def test_ai_plan_json_request_contract_and_impact_classification(tmp_path: Path, monkeypatch):
    """Verify that /api/v1/ai/plan accepts JSON body with vulnerability_type and outputs step impact classification."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.core import engagement as core_eng
    from nyx.application.ai_service import AIService
    from nyx.web.auth import get_or_create_api_token

    monkeypatch.chdir(tmp_path)
    core_eng.init_engagement("api.target.com", reset=True, force=True)

    app = create_app()
    client = TestClient(app)
    token = get_or_create_api_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test POST with JSON body containing target and vulnerability_type
    payload = {
        "target": "api.target.com",
        "vulnerability_type": "SQL Injection",
        "context": {"target": "api.target.com"}
    }
    resp = client.post("/api/v1/ai/plan", json=payload, headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data.get("success") is True
    plan = data.get("data", {})
    assert plan.get("target") == "api.target.com"
    assert plan.get("vulnerability_type") == "SQL Injection"
    assert "analysis" in plan
    assert "recommended_focus" in plan
    assert "steps" in plan
    assert len(plan["steps"]) >= 4

    # 2. Verify destructive/non-destructive classification and justifications on steps
    for step in plan["steps"]:
        assert "impact_class" in step
        assert step["impact_class"] in ("NON_DESTRUCTIVE", "DESTRUCTIVE")
        assert "impact_justification" in step
        assert len(step["impact_justification"]) > 5

    # 3. Verify targeted vulnerability step exists in plan
    reasons = [s.get("reason", "") for s in plan["steps"]]
    assert any("SQL" in r for r in reasons)

    # 4. Test backward-compatible query param POST
    resp_query = client.post("/api/v1/ai/plan?target=api.target.com", headers=headers)
    assert resp_query.status_code == 200

    # 5. Verify execute_plan handles nyx-validate gracefully without ValueError
    from nyx.ai.planner import MissionPlanner
    planner = MissionPlanner(base_dir=tmp_path)
    plan_with_validate = dict(plan)
    plan_with_validate["steps"] = list(plan.get("steps", [])) + [{
        "step": 99,
        "name": "Manual Validation Step",
        "action": "validate",
        "tool": "nyx-validate",
        "impact_class": "DESTRUCTIVE",
        "reason": "CUSTOM_VALIDATION",
    }]
    exec_res = planner.execute_plan(plan_with_validate, active_permitted=False)
    assert exec_res.get("status") == "success"
    validate_steps = [s for s in exec_res.get("step_results", []) if s.get("tool") == "nyx-validate"]
    assert len(validate_steps) >= 1
    assert validate_steps[0]["result"]["status"] == "manual_action_required"
    assert "Manual verification required" in validate_steps[0]["result"]["message"]

    # 6. Verify standalone execute_step works for individual steps in isolation
    for step in plan["steps"]:
        single_res = planner.execute_step(step, "api.target.com", active_permitted=False)
        assert "step" in single_res
        assert "tool" in single_res
        assert "result" in single_res


def test_autonomous_loop_lifecycle_and_safety_guards(tmp_path: Path, monkeypatch):
    """Verify run_autonomous_loop sequential execution, destructive pause, and completion."""
    from nyx.core import engagement as core_eng
    from nyx.ai.planner import MissionPlanner
    from nyx.application.recon_service import ReconService

    monkeypatch.chdir(tmp_path)
    core_eng.init_engagement("auto.target.com", reset=True, force=True)

    # Mock ReconService.run_recon to prevent real DNS queries against test domains
    def fake_recon(self, target: str, **kwargs):
        d = tmp_path / ".engagement"
        if d.exists():
            (d / "endpoints.json").write_text(json.dumps([{"url": f"https://{target}/api/v1/resource", "host": target}]), encoding="utf-8")
            (d / "technologies.json").write_text(json.dumps({"web": ["Express"]}), encoding="utf-8")
        return {"status": "success", "sync_total": 1, "live_count": 1}

    monkeypatch.setattr(ReconService, "run_recon", fake_recon)

    planner = MissionPlanner(base_dir=tmp_path)

    # Mock analyze for fast, deterministic unit test behavior
    planner.ai_manager.analyze = lambda ctx, prompt=None, provider_name=None: {
        "selected_index": 0,
        "decision": "proceed",
        "reasoning": "Step selection",
    }

    # 1. Test full non-destructive sequence running until candidate exhaustion or destructive pause
    res = planner.run_autonomous_loop("auto.target.com", active_permitted=False, max_iterations=10)
    assert res["status"] in ("complete", "paused_for_approval")
    assert len(res["iterations"]) >= 1
    for it in res["iterations"]:
        assert "step" in it
        assert "result" in it
        assert "ai_reasoning" in it
        assert it["step"]["impact_class"] == "NON_DESTRUCTIVE"

    # Verify second invocation immediately finishes or pauses without executing new iterations
    res_second = planner.run_autonomous_loop("auto.target.com", active_permitted=False, max_iterations=5)
    assert res_second["status"] in ("complete", "paused_for_approval")
    assert len(res_second["iterations"]) == 0

    # 2. Test pause on DESTRUCTIVE step without executing it
    # Mock _select_steps to return a destructive step as first candidate
    original_select = planner._select_steps
    def mock_destructive_select(ctx):
        return [{
            "step": 1,
            "name": "Active Payload Injection",
            "action": "payload_injection",
            "tool": "nuclei",
            "description": "Active exploit verification.",
            "impact_class": "DESTRUCTIVE",
            "impact_justification": "Modifies database state.",
            "policy_status": "PENDING_POLICY_VALIDATION",
        }]

    planner._select_steps = mock_destructive_select
    try:
        pause_res = planner.run_autonomous_loop("auto.target.com", active_permitted=True)
        assert pause_res["status"] == "paused_for_approval"
        assert pause_res["pending_step"]["impact_class"] == "DESTRUCTIVE"
        assert len(pause_res["iterations"]) == 0
    finally:
        planner._select_steps = original_select

    # 3. Test AI candidate selection and out-of-bounds index fallback safety
    core_eng.init_engagement("invalid.target.com", reset=True, force=True, base_dir=tmp_path)
    planner_invalid = MissionPlanner(base_dir=tmp_path)
    # Test valid selected_index from AI
    planner_invalid.ai_manager.analyze = lambda ctx, prompt=None, provider_name=None: {"selected_index": 0, "decision": "proceed", "reasoning": "Prioritizing discovery"}
    res_ai_valid = planner_invalid.run_autonomous_loop("invalid.target.com", active_permitted=False, max_iterations=1)
    assert len(res_ai_valid["iterations"]) <= 1

    # Test invalid / out-of-bounds selected_index fails closed with ai_unavailable status
    planner_invalid.ai_manager.analyze = lambda ctx, prompt=None, provider_name=None: {"selected_index": 9999, "decision": "proceed", "reasoning": "Malformed index"}
    res_ai_invalid = planner_invalid.run_autonomous_loop("invalid.target.com", active_permitted=False, max_iterations=1)
    assert res_ai_invalid["status"] == "ai_unavailable"
    assert res_ai_invalid["ai_degraded"] is True

    # 4. Test decision branching: skip, escalate, and malformed
    # 4.a. Test decision == "skip" (step not executed, iteration recorded with skip marker, loop continues)
    core_eng.init_engagement("skip.target.com", reset=True, force=True, base_dir=tmp_path)
    planner_skip = MissionPlanner(base_dir=tmp_path)
    planner_skip.ai_manager.analyze = lambda ctx, prompt=None, provider_name=None: {"selected_index": 0, "decision": "skip", "reasoning": "Hypothesis disproven - skip"}
    res_skip = planner_skip.run_autonomous_loop("skip.target.com", active_permitted=False, max_iterations=2)
    assert len(res_skip["iterations"]) >= 1
    assert res_skip["iterations"][0]["result"]["status"] == "skipped"
    assert "AI decision signalled skip" in res_skip["iterations"][0]["result"]["reason"]

    # 4.b. Test decision == "escalate" (loop stops immediately, status == "escalated", no execution)
    core_eng.init_engagement("escalate.target.com", reset=True, force=True, base_dir=tmp_path)
    planner_esc = MissionPlanner(base_dir=tmp_path)
    planner_esc.ai_manager.analyze = lambda ctx, prompt=None, provider_name=None: {"selected_index": 0, "decision": "escalate", "reasoning": "Hypothesis confirmed - escalate immediately"}
    res_esc = planner_esc.run_autonomous_loop("escalate.target.com", active_permitted=False, max_iterations=5)
    assert res_esc["status"] == "escalated"
    assert "escalated_step" in res_esc
    assert res_esc["escalated_step"] is not None
    assert len(res_esc["iterations"]) == 0

    # 4.c. Test decision missing or malformed string falls back to "proceed"
    core_eng.init_engagement("malformed.target.com", reset=True, force=True, base_dir=tmp_path)
    planner_mal = MissionPlanner(base_dir=tmp_path)
    planner_mal.ai_manager.analyze = lambda ctx, prompt=None, provider_name=None: {"selected_index": 0, "decision": "UNKNOWN_RANDOM_VALUE", "reasoning": "Degrade to proceed"}
    res_mal = planner_mal.run_autonomous_loop("malformed.target.com", active_permitted=False, max_iterations=1)
    assert len(res_mal["iterations"]) == 1
    assert res_mal["iterations"][0]["result"].get("status") != "skipped"

    # 5. Test out-of-scope immediate error
    oops_res = planner.run_autonomous_loop("unauthorized-external-domain.com")
    assert oops_res["status"] == "error"
    assert oops_res["error"] == "out of scope"


def test_ai_autonomous_api_route_and_cli_smoke(tmp_path: Path, monkeypatch, capsys):
    """Test POST /api/v1/ai/autonomous-run API route and nyx ai autonomous CLI command."""
    import argparse
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.core import engagement as core_eng
    from nyx.ai.planner import MissionPlanner
    from nyx.application.recon_service import ReconService
    from nyx_cli.cli import cmd_ai

    monkeypatch.chdir(tmp_path)
    core_eng.init_engagement("auto.target.com", reset=True, force=True)

    # Mock ReconService.run_recon to prevent real DNS queries against test domains
    def fake_recon(self, target: str, **kwargs):
        d = tmp_path / ".engagement"
        if d.exists():
            (d / "endpoints.json").write_text(json.dumps([{"url": f"https://{target}/api/v1/resource", "host": target}]), encoding="utf-8")
            (d / "technologies.json").write_text(json.dumps({"web": ["Express"]}), encoding="utf-8")
        return {"status": "success", "sync_total": 1, "live_count": 1}

    monkeypatch.setattr(ReconService, "run_recon", fake_recon)

    app = create_app()
    client = TestClient(app)
    token = get_or_create_api_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. API Route integration test
    # Mock MissionPlanner.ai_manager.analyze within AIService
    mock_analyze = lambda self, ctx, prompt=None, provider_name=None: {
        "selected_index": 0,
        "decision": "proceed",
        "reasoning": "API route execution",
    }
    from nyx.ai.manager import AIManager
    monkeypatch.setattr(AIManager, "analyze", mock_analyze)

    resp = client.post(
        "/api/v1/ai/autonomous-run",
        json={"target": "auto.target.com", "max_iterations": 2, "active_permitted": False},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "status" in data
    assert data.get("target") == "auto.target.com"
    assert "iterations" in data

    # 2. Out-of-scope target returns 400
    resp_oos = client.post(
        "/api/v1/ai/autonomous-run",
        json={"target": "unauthorized-domain.com", "max_iterations": 1},
        headers=headers,
    )
    assert resp_oos.status_code == 400

    # 3. CLI command smoke test (both human and JSON format)
    args_human = argparse.Namespace(
        ai_subcommand="autonomous",
        target="auto.target.com",
        provider=None,
        active_permitted=False,
        max_iterations=1,
        json=False,
    )
    exit_code_human = cmd_ai(args_human)
    assert exit_code_human == 0

    args_json = argparse.Namespace(
        ai_subcommand="autonomous",
        target="auto.target.com",
        provider=None,
        active_permitted=False,
        max_iterations=1,
        json=True,
    )
    exit_code_json = cmd_ai(args_json)
    assert exit_code_json == 0

    # 4. Confirm destructive step still pauses even with active_permitted=True
    planner = MissionPlanner(base_dir=tmp_path)
    planner._select_steps = lambda ctx: [{
        "step": 1,
        "name": "Database Dropper",
        "action": "sql_exec",
        "tool": "nuclei",
        "description": "Destructive DB manipulation.",
        "impact_class": "DESTRUCTIVE",
        "impact_justification": "Modifies production database state.",
        "policy_status": "PENDING_POLICY_VALIDATION",
    }]
    res_dest = planner.run_autonomous_loop("auto.target.com", active_permitted=True, max_iterations=2)
    assert res_dest["status"] == "paused_for_approval"
    assert res_dest["pending_step"]["impact_class"] == "DESTRUCTIVE"
    assert len(res_dest["iterations"]) == 0


def test_agent_approval_executes_step_and_deny_persists_exclusion(tmp_path: Path, monkeypatch):
    """Verify POST /api/v1/agent/approve/{id} executes real step with active_permitted=True, and deny persists exclusion."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.core import engagement as core_eng
    from nyx.ai.planner import MissionPlanner
    from nyx.agent import NYXAgent

    monkeypatch.chdir(tmp_path)
    core_eng.init_engagement("approval.target.com", reset=True, force=True)

    app = create_app()
    client = TestClient(app)
    token = get_or_create_api_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Propose a destructive step with full step metadata
    dest_step = {
        "step": 1,
        "name": "Live Destructive DB Probe",
        "tool": "nuclei",
        "action": "vuln_probe",
        "impact_class": "DESTRUCTIVE",
        "impact_justification": "Modifies production database table.",
        "params": {"test_id": 99},
        "target": "approval.target.com",
    }
    prop_resp = client.post(
        "/api/v1/agent/propose",
        json={
            "target": "approval.target.com",
            "action": "Live Destructive DB Probe",
            "reason": "Modifies production database table.",
            "tool_name": "nuclei",
            "risk": "High",
            "step": dest_step,
            "impact_class": "DESTRUCTIVE",
            "impact_justification": "Modifies production database table.",
        },
        headers=headers,
    )
    assert prop_resp.status_code == 200, prop_resp.text
    prop_data = prop_resp.json()
    action_id_approve = prop_data.get("action_id") or prop_data.get("data", {}).get("action_id")
    assert action_id_approve is not None

    # Verify pending approvals list retains full metadata
    apps_resp = client.get("/api/v1/agent/approvals", headers=headers)
    assert apps_resp.status_code == 200
    apps_data = apps_resp.json()
    pending = apps_data.get("pending") or apps_data.get("data", {}).get("pending", [])
    matched = [p for p in pending if p.get("action_id") == action_id_approve]
    assert len(matched) == 1
    assert matched[0].get("impact_class") == "DESTRUCTIVE"
    assert matched[0].get("tool") in ("nuclei", "tool")

    # 2. Test Approve: actually calls execute_step with active_permitted=True
    approve_resp = client.post(f"/api/v1/agent/approve/{action_id_approve}", headers=headers)
    assert approve_resp.status_code == 200, approve_resp.text
    approve_data = approve_resp.json()
    res_record = approve_data.get("data") or approve_data
    assert res_record.get("status") == "approved_and_executed"
    assert "execution_result" in res_record
    assert res_record["execution_result"].get("tool") == "nuclei"
    assert "result" in res_record

    # 3. Test Deny: propose another action and deny it
    prop_deny_resp = client.post(
        "/api/v1/agent/propose",
        json={
            "target": "approval.target.com",
            "action": "Technology Fingerprinting",
            "reason": "INITIAL_HOST_DISCOVERY",
            "tool_name": "httpx",
            "risk": "Low",
        },
        headers=headers,
    )
    assert prop_deny_resp.status_code == 200
    action_id_deny = (prop_deny_resp.json().get("data") or prop_deny_resp.json()).get("action_id")

    deny_resp = client.post(f"/api/v1/agent/deny/{action_id_deny}?reason=Excluded+by+client", headers=headers)
    assert deny_resp.status_code == 200, deny_resp.text
    deny_data = deny_resp.json()
    assert (deny_data.get("data") or deny_data).get("status") == "denied"

    # 4. Verify Deny persists into tested_vectors.json and planner excludes it from future candidate generation
    planner = MissionPlanner(base_dir=tmp_path)
    ctx = planner.context_engine.get_target_context("approval.target.com")
    tested_vecs = ctx.get("tested_vectors", [])
    denied_records = [tv for tv in tested_vecs if tv.get("result") == "denied_by_operator"]
    assert len(denied_records) > 0

    # Ensure _select_steps() excludes the denied httpx step from candidate list
    steps = planner._select_steps(ctx)
    tools_in_steps = [s.get("tool") for s in steps]
    assert "httpx" not in tools_in_steps


def test_ai_manager_env_provider_selection(monkeypatch):
    """Verify AIManager honors auto-detection, NYX_PREFER_LOCAL, and environment variables without hardcoded gemini default."""
    from nyx.ai.manager import AIManager, detect_default_provider

    # Default auto-detect when no provider env var set
    monkeypatch.delenv("NYX_AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("NYX_PREFER_LOCAL", raising=False)
    monkeypatch.delenv("PREFER_LOCAL", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    mgr_default = AIManager()
    assert mgr_default.active_provider_name == detect_default_provider()
    assert mgr_default.active_provider_name == "groq"

    # NYX_PREFER_LOCAL forces local even if GROQ_API_KEY is present
    monkeypatch.setenv("NYX_PREFER_LOCAL", "true")
    assert detect_default_provider() == "local"
    mgr_local = AIManager()
    assert mgr_local.active_provider_name == "local"

    # Explicit NYX_AI_PROVIDER still takes top priority over NYX_PREFER_LOCAL
    monkeypatch.setenv("NYX_AI_PROVIDER", "claude")
    assert detect_default_provider() == "claude"
    mgr_explicit_env = AIManager()
    assert mgr_explicit_env.active_provider_name == "claude"

    # Cleanup prefer local
    monkeypatch.delenv("NYX_AI_PROVIDER", raising=False)
    monkeypatch.delenv("NYX_PREFER_LOCAL", raising=False)

    # NYX_AI_PROVIDER env var
    monkeypatch.setenv("NYX_AI_PROVIDER", "groq")
    mgr_groq = AIManager()
    assert mgr_groq.active_provider_name == "groq"

    # AI_PROVIDER fallback
    monkeypatch.delenv("NYX_AI_PROVIDER", raising=False)
    monkeypatch.setenv("AI_PROVIDER", "grok")
    mgr_grok = AIManager()
    assert mgr_grok.active_provider_name == "grok"

    # Explicit argument takes precedence over env var
    mgr_explicit = AIManager(default_provider="claude")
    assert mgr_explicit.active_provider_name == "claude"


def test_reasoning_engine_env_provider_selection(monkeypatch):
    """Verify ReasoningEngine honors NYX_AI_PROVIDER environment variable."""
    from nyx.agent.reasoning import ReasoningEngine

    monkeypatch.setenv("NYX_AI_PROVIDER", "groq")
    engine = ReasoningEngine()
    assert engine.provider_name == "groq"
    assert engine.ai_manager.active_provider_name == "groq"


def test_cli_mission_run_provider_flag():
    """Verify CLI parser for mission run and run-mission accepts --provider flag."""
    from nyx_cli.cli import build_parser

    parser = build_parser()
    args_mission = parser.parse_args(["mission", "run", "example.com", "--provider", "groq"])
    assert args_mission.target == "example.com"
    assert args_mission.provider == "groq"

    args_run_mission = parser.parse_args(["run-mission", "example.com", "--provider", "grok"])
    assert args_run_mission.target == "example.com"
    assert args_run_mission.provider == "grok"


def test_fleet_and_controller_provider_threading(tmp_path):
    """Verify provider_name is properly threaded into FleetService, WorkerService, and AgentController."""
    from nyx.application.fleet_service import FleetService
    from nyx.application.worker_service import WorkerService

    # Explicit provider_name threaded into FleetService and specialized agents
    fleet = FleetService(provider_name="groq", base_dir=tmp_path)
    assert fleet.controller.provider_name == "groq"
    res = fleet.create_agent("recon", "test.com")
    agent_id = res.data["agent_id"]
    agent_inst = fleet.controller.registry.get_agent(agent_id)
    assert agent_inst.provider_name == "groq"
    assert agent_inst.inner_agent.reasoning_engine.provider_name == "groq"

    # WorkerService controller provider threading
    worker = WorkerService(provider_name="grok")
    assert worker.controller.provider_name == "grok"


def test_tool_based_validation_destructive_impact_classification(tmp_path):
    """Verify that all tool-based validation steps are classified as DESTRUCTIVE by default."""
    from nyx.ai.planner import MissionPlanner
    planner = MissionPlanner(base_dir=tmp_path)

    for vuln in ["sql_injection", "prototype_pollution", "xss", "ssrf", "auth_bypass", "rce", "idor"]:
        context = {
            "target": "target.local",
            "phase": "ANALYSIS",
            "endpoints": ["http://target.local/api/test"],
            "technologies": ["express"],
            "vulnerability_type": vuln,
            "has_hypothesis": True,
            "hypothesis_findings": ["FH-2026-001"],
        }
        steps = planner._select_steps(context)
        val_steps = [s for s in steps if s.get("impact_class") == "DESTRUCTIVE"]
        assert len(val_steps) >= 1, f"Expected validation step for {vuln}"
        for s in val_steps:
            assert s.get("impact_class") == "DESTRUCTIVE", f"Expected DESTRUCTIVE for {vuln}, got {s.get('impact_class')}"


def test_sqlmap_adapter_lifecycle():
    """Verify SqlmapAdapter command building and result parsing."""
    from nyx.execution.adapters.sqlmap import SqlmapAdapter
    from nyx.execution.adapters import get_adapter

    adapter = get_adapter("sqlmap")
    assert adapter is not None
    assert isinstance(adapter, SqlmapAdapter)

    valid, _ = adapter.validate("http://target.local/login")
    assert valid

    cmd = adapter.build_command("http://target.local/login", ["--technique=BEUSTQ"])
    assert any("sqlmap" in c for c in cmd)
    assert "-u" in cmd
    assert "http://target.local/login" in cmd
    assert "--batch" in cmd
    assert "--technique=BEUSTQ" in cmd

    raw_stdout = (
        "--- [INFO] testing connection\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "back-end DBMS: SQLite\n"
        "sqlmap identified the following injection points with a total of 50 HTTP(s) requests:\n"
    )
    parsed = adapter.parse_result(raw_stdout, "")
    assert parsed["parsed"] is True
    assert parsed["is_vulnerable"] is True
    assert parsed["dbms"] == "SQLite"
    assert len(parsed["vulnerabilities"]) >= 1


def test_nuclei_template_mapping_for_vuln_classes():
    """Verify template mapping maps vulnerability classes to existing official templates without authoring custom payloads."""
    from nyx.execution.adapters.nuclei import get_nuclei_template_for_vuln

    proto = get_nuclei_template_for_vuln("prototype pollution")
    assert proto is not None
    assert "prototype-pollution" in proto["template_id"] or "prototype-pollution" in proto["tags"]

    sqli = get_nuclei_template_for_vuln("sql injection")
    assert sqli is not None
    assert "sqli" in sqli["template_id"] or "sqli" in sqli["tags"]

    xss = get_nuclei_template_for_vuln("xss")
    assert xss is not None
    assert "xss" in xss["template_id"] or "xss" in xss["tags"]


def test_tool_validation_policy_gate_and_evidence_capture(tmp_path: Path, monkeypatch):
    """Verify policy gate prevents unauthorized/out-of-scope validation, and active validation records evidence."""
    from nyx.core import engagement as core_eng
    from nyx.ai.planner import MissionPlanner
    from nyx.execution.engine import ExecutionEngine
    from unittest.mock import patch, MagicMock

    monkeypatch.chdir(tmp_path)
    core_eng.init_engagement("sec.target.com", reset=True, force=True)

    planner = MissionPlanner(base_dir=tmp_path)

    # 1. Blocked when active_permitted=False
    step = {
        "step": 1,
        "name": "Prototype Pollution Validation",
        "tool": "nyx-validate",
        "reason": "prototype_pollution_validation",
        "target": "http://sec.target.com/api/test",
        "evidence": ["FH-2026-001"],
        "impact_class": "DESTRUCTIVE",
    }
    res_no_active = planner.execute_step(step, "http://sec.target.com/api/test", active_permitted=False)
    assert res_no_active["result"]["status"] == "manual_action_required"

    # 2. Blocked when target is OUT OF SCOPE
    step_oos = dict(step)
    step_oos["target"] = "http://unauthorized.evil.com/api/test"
    res_oos = planner.execute_step(step_oos, "http://unauthorized.evil.com/api/test", active_permitted=True)
    assert res_oos["result"]["status"] == "blocked_by_policy"

    # 3. Executes and records evidence when in-scope and active_permitted=True
    core_eng.init_engagement("sec.target.com", reset=True, force=True)
    auth_yaml = tmp_path / ".engagement" / "authorization.yaml"
    auth_yaml.write_text("authorized: true\nallow_active: true\nscope:\n  - sec.target.com\n", encoding="utf-8")

    # Create hypothesis finding in workspace
    from nyx.core.findings import create_finding
    f_res = create_finding(
        title="Prototype Pollution Candidate",
        severity="High",
        endpoint="http://sec.target.com/api/test",
        parameter="proto",
        vulnerability="Prototype Pollution",
        base_dir=tmp_path,
    )
    fid = f_res.get("finding_id")

    mock_exec_res = MagicMock()
    mock_exec_res.execution_id = "EXEC-MOCK-1234"
    mock_exec_res.status = "COMPLETED"
    mock_exec_res.exit_code = 0
    mock_exec_res.stdout = '{"template-id": "client-side-prototype-pollution", "info": {"name": "Prototype Pollution", "severity": "high"}}\n'
    mock_exec_res.stderr = ""
    mock_exec_res.metadata = {
        "vulnerabilities": [{"template_id": "client-side-prototype-pollution", "name": "Prototype Pollution", "severity": "high"}]
    }

    step_active = dict(step)
    step_active["evidence"] = [fid]

    with patch.object(ExecutionEngine, "execute", return_value=mock_exec_res):
        res_active = planner.execute_step(step_active, "http://sec.target.com/api/test", active_permitted=True)
        assert res_active["result"]["status"] == "success"
        assert res_active["result"]["tool_used"] == "nuclei"
        assert len(res_active["result"]["evidence_ids"]) >= 1
        assert res_active["result"]["execution_id"] == "EXEC-MOCK-1234"


def test_recon_registers_execution_record(tmp_path: Path, monkeypatch):
    """Test that passive recon completion logs an EXEC-XXXXXXXX record in executions.json."""
    from nyx.application.recon_service import ReconService
    from nyx.application.execution_service import ExecutionService
    from nyx.core import recon as core_recon

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".engagement").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".engagement" / "target.yaml").write_text("domain: test.example.com\nscope:\n  - test.example.com\n", encoding="utf-8")
    (tmp_path / ".engagement" / "authorization.yaml").write_text("authorized: true\nmode: testing\nscope:\n  - test.example.com\n", encoding="utf-8")

    # Mock low-level network calls in core_recon to run fast
    with patch("nyx.core.recon.recon_subdomains_via_crtsh", return_value=set()), \
         patch("nyx.core.recon.recon_subdomains_via_subfinder", return_value=set()), \
         patch("nyx.core.recon.recon_resolve", return_value=["127.0.0.1"]), \
         patch("nyx.core.recon.recon_http_probe", return_value={"url": "https://test.example.com", "status": 200, "technologies": ["nginx"]}), \
         patch("nyx.core.recon.run_content_discovery", return_value=[]):
        
        recon_service = ReconService()
        res = recon_service.run_recon("test.example.com")
        assert res["success"] is True
        assert res["data"].get("execution_id") is not None
        assert str(res["data"]["execution_id"]).startswith("EXEC-")

        # Verify ExecutionService.get_history sees the record
        exec_service = ExecutionService(base_dir=tmp_path)
        hist_res = exec_service.get_history(limit=10, target="test.example.com")
        assert hist_res.is_success is True
        history = hist_res.data.get("history", [])
        assert len(history) >= 1
        recon_exec = next((h for h in history if h.get("tool_name") == "nyx-recon"), None)
        assert recon_exec is not None
        assert recon_exec["target"] == "test.example.com"
        assert recon_exec["execution_id"].startswith("EXEC-")
        assert recon_exec["execution_class"] == "PASSIVE_READ"


def test_autonomous_mission_dedup_vs_fresh_empty_message(tmp_path: Path, monkeypatch):
    """Test that autonomous mission complete response distinguishes dedup from fresh empty targets."""
    from nyx.ai.planner import MissionPlanner

    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("domain: fresh.target.com\nscope:\n  - fresh.target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nmode: testing\nscope:\n  - fresh.target.com\n", encoding="utf-8")

    # Case A: Fresh target with 0 endpoints and 0 tested vectors
    planner = MissionPlanner(base_dir=tmp_path)
    # If endpoints is empty, candidates generate httpx/classify, but if we mock _select_steps to return []
    with patch.object(planner, "_select_steps", return_value=[]):
        res_fresh = planner.run_autonomous_loop(target="fresh.target.com", active_permitted=False)
        assert res_fresh["status"] == "complete"
        assert res_fresh["reason"] == "no_remaining_candidates"
        assert res_fresh["is_dedup"] is False
        assert "No candidate vectors found" in res_fresh["message"]

    # Case B: Prior run recorded tested vectors for the target
    (eng_dir / "tested_vectors.json").write_text(json.dumps([
        {"vector": "graphql_surface_detected", "endpoint": "fresh.target.com", "result": "tested_success"}
    ]), encoding="utf-8")

    planner_dedup = MissionPlanner(base_dir=tmp_path)
    with patch.object(planner_dedup, "_select_steps", return_value=[]):
        res_dedup = planner_dedup.run_autonomous_loop(target="fresh.target.com", active_permitted=False)
        assert res_dedup["status"] == "complete"
        assert res_dedup["reason"] == "no_remaining_candidates"
        assert res_dedup["is_dedup"] is True
        assert res_dedup["tested_vectors_count"] >= 1
        assert "All candidate vectors already evaluated in a prior run" in res_dedup["message"]
        assert "1 vector previously tested" in res_dedup["message"]


def test_autonomous_loop_recon_bootstrap(tmp_path: Path, monkeypatch):
    """Test that autonomous mission loop on a target with 0 endpoints auto-bootstraps recon first."""
    from nyx.ai.planner import MissionPlanner

    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("domain: auto.target.com\nscope:\n  - auto.target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nmode: testing\nscope:\n  - auto.target.com\n", encoding="utf-8")

    mock_recon_called = False

    def mock_run_recon(target: str, **kwargs):
        nonlocal mock_recon_called
        mock_recon_called = True
        # Simulate recon populating endpoints and technologies
        (eng_dir / "endpoints.json").write_text(json.dumps([
            {"url": "https://auto.target.com/api/users", "host": "auto.target.com"},
            {"url": "https://auto.target.com/login", "host": "auto.target.com"}
        ]), encoding="utf-8")
        (eng_dir / "technologies.json").write_text(json.dumps({
            "frameworks": ["Express", "Node.js"]
        }), encoding="utf-8")
        return {"status": "success", "sync_total": 2}

    planner = MissionPlanner(base_dir=tmp_path)
    with patch("nyx.application.recon_service.ReconService.run_recon", side_effect=mock_run_recon), \
         patch.object(planner.ai_manager, "analyze", return_value={"selected_index": 0, "decision": "proceed", "reasoning": "Test AI decision"}):
        res = planner.run_autonomous_loop(target="auto.target.com", active_permitted=False, max_iterations=2)
        assert mock_recon_called is True
        assert len(res.get("iterations", [])) >= 1
        first_step = res["iterations"][0]["step"]
        assert first_step.get("tool") == "nyx-classify"


def test_url_classification_prioritizes_functional_surfaces_over_php_extension():
    """Verify that specific functional surfaces (auth, upload, sqli, xss) take priority over .php extension,
    and COMMAND_INJECTION_SURFACE requires explicit command-execution indicators."""
    from nyx.application.analysis_service import AnalysisService

    svc = AnalysisService()

    # 1. Login page ending in .php must classify as AUTH_IDENTITY_SURFACE, NOT COMMAND_INJECTION_SURFACE
    c_login = svc.classify_url("https://example.com/admin/login.php")
    assert c_login["category"] == "AUTH_IDENTITY_SURFACE"
    assert "hunt-auth-bypass" in c_login["skills"]

    # 2. File upload page ending in .php must classify as FILE_UPLOAD_SURFACE
    c_upload = svc.classify_url("https://example.com/upload.php")
    assert c_upload["category"] == "FILE_UPLOAD_SURFACE"

    # 3. Search query ending in .php must classify as XSS or SQLI surface
    c_search = svc.classify_url("https://example.com/search.php?q=apple")
    assert c_search["category"] in ("XSS_SURFACE", "SQLI_SURFACE")

    # 4. Genuine command injection with explicit indicators must classify as COMMAND_INJECTION_SURFACE
    c_ping = svc.classify_url("https://example.com/network/ping.php?host=127.0.0.1")
    assert c_ping["category"] == "COMMAND_INJECTION_SURFACE"

    c_cmd = svc.classify_url("https://example.com/utilities/exec?cmd=id")
    assert c_cmd["category"] == "COMMAND_INJECTION_SURFACE"

    c_shell = svc.classify_url("https://example.com/command-injection/run")
    assert c_shell["category"] == "COMMAND_INJECTION_SURFACE"


def test_auto_approve_executes_destructive_step_and_records_approval_history(tmp_path: Path):
    """Verify that auto_approve=True executes DESTRUCTIVE steps without pausing,
    records the approval in approvals.json with approved_by='auto', and updates approval history."""
    from nyx.ai.planner import MissionPlanner
    from nyx.agent.approval import ApprovalSystem
    from nyx.application.agent_service import AgentService

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: example.com\nscope:\n  - example.com\n  - '*.example.com'\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nmode: testing\nscope:\n  - example.com\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps([{"url": "https://example.com/login", "host": "example.com"}]), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps({"web": ["express"]}), encoding="utf-8")

    destructive_step = {
        "step": 1,
        "name": "SQLMap Active Injection Scan",
        "tool": "sqlmap",
        "action": "active_validation",
        "target": "https://example.com/api/user?id=1",
        "impact_class": "DESTRUCTIVE",
        "impact_justification": "Active SQL injection fuzzing modifies database state.",
        "reason": "SQL_INJECTION",
    }

    planner = MissionPlanner(base_dir=tmp_path)

    with patch.object(planner, "_select_steps", return_value=[destructive_step]), \
         patch.object(planner.ai_manager, "analyze", return_value={"selected_index": 0, "decision": "proceed", "reasoning": "Execute active validation"}), \
         patch.object(planner, "execute_step", return_value={"step": 1, "name": "SQLMap Active Injection Scan", "tool": "sqlmap", "result": {"status": "success", "stdout": "sqlmap output"}}):

        res = planner.run_autonomous_loop(
            target="example.com",
            active_permitted=True,
            max_iterations=1,
            auto_approve=True,
        )

        # 1. Mission did NOT pause for operator approval
        assert res.get("status") != "paused_for_approval"
        assert len(res.get("iterations", [])) == 1
        it0 = res["iterations"][0]
        assert it0.get("status") == "approved_and_executed"
        assert it0.get("approved_by") == "auto"
        assert it0.get("action_id", "").startswith("ACT-")

        # 2. approvals.json has the auto-approved record
        app_sys = ApprovalSystem(base_dir=tmp_path)
        history = app_sys.get_approval_history(target="example.com")
        assert len(history) == 1
        record = history[0]
        assert record["status"] == "APPROVED"
        assert record["approved_by"] == "auto"
        assert record["impact_class"] == "DESTRUCTIVE"
        assert "approved_at" in record

        # 3. AgentService reflects the auto-approval in approvals API
        agent_svc = AgentService(base_dir=tmp_path)
        approvals_data = agent_svc.get_approvals().data
        assert approvals_data["pending_count"] == 0
        assert approvals_data["approved_count"] == 1
        assert len(approvals_data["approved"]) == 1
        assert approvals_data["approved"][0]["approved_by"] == "auto"


def test_auto_approve_respects_scope_and_policy_boundaries(tmp_path: Path):
    """Verify that auto_approve=True still enforces scope and policy boundaries,
    failing closed if targets are out-of-scope or blocked by security policies."""
    from nyx.ai.planner import MissionPlanner
    from nyx.agent.approval import ApprovalSystem

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: authorized.com\nscope:\n  - authorized.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nmode: testing\nscope:\n  - authorized.com\n", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)

    # 1. Out-of-scope mission target must fail closed immediately
    res_oos = planner.run_autonomous_loop(
        target="out-of-scope.com",
        active_permitted=True,
        max_iterations=1,
        auto_approve=True,
    )
    assert res_oos.get("status") == "error"
    assert res_oos.get("error") == "out of scope"

    # No approvals should be generated
    app_sys = ApprovalSystem(base_dir=tmp_path)
    assert len(app_sys.get_approval_history()) == 0


def test_manual_approval_remains_default(tmp_path: Path):
    """Verify that auto_approve=False (the default) continues to pause for manual operator approval."""
    from nyx.ai.planner import MissionPlanner
    from nyx.agent.approval import ApprovalSystem

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: example.com\nscope:\n  - example.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nmode: testing\nscope:\n  - example.com\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps([{"url": "https://example.com/login", "host": "example.com"}]), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps({"web": ["express"]}), encoding="utf-8")

    destructive_step = {
        "step": 1,
        "name": "SQLMap Active Injection Scan",
        "tool": "sqlmap",
        "action": "active_validation",
        "target": "https://example.com/api/user?id=1",
        "impact_class": "DESTRUCTIVE",
        "impact_justification": "Active SQL injection fuzzing modifies database state.",
        "reason": "SQL_INJECTION",
    }

    planner = MissionPlanner(base_dir=tmp_path)

    with patch.object(planner, "_select_steps", return_value=[destructive_step]), \
         patch.object(planner.ai_manager, "analyze", return_value={"selected_index": 0, "decision": "proceed", "reasoning": "Execute active validation"}):

        # auto_approve defaults to False
        res = planner.run_autonomous_loop(
            target="example.com",
            active_permitted=True,
            max_iterations=1,
        )

        assert res.get("status") == "paused_for_approval"
        assert "pending_step" in res
        assert res.get("pending_step", {}).get("name") == "SQLMap Active Injection Scan"

        app_sys = ApprovalSystem(base_dir=tmp_path)
        pending = app_sys.get_pending_approvals(target="example.com")
        assert len(pending) == 1
        assert pending[0]["tool_name"] == "sqlmap"
        assert len(app_sys.get_approval_history(target="example.com")) == 0


def test_surface_recon_endpoint_executes_without_name_error(tmp_path: Path):
    """Verify that POST /api/v1/surface/recon executes without NameError: name 'asyncio' is not defined."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from unittest.mock import patch

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: example.com\nscope:\n  - example.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nmode: testing\nscope:\n  - example.com\n", encoding="utf-8")

    app = create_app()
    token = get_or_create_api_token()
    client = TestClient(app)
    with patch("nyx.application.recon_service.ReconService.run_recon", return_value={"status": "success", "endpoints": []}):
        resp = client.post("/api/v1/surface/recon?target=example.com", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True or data.get("status") == "success"


def test_active_mission_tracker_lifecycle():
    """Verify ActiveMissionTracker tracks each lifecycle stage (start, update_progress, pause, complete)."""
    from nyx.ai.tracker import active_mission_tracker
    active_mission_tracker.reset()

    # 1. Idle state
    idle = active_mission_tracker.get_status()
    assert idle["is_running"] is False
    assert idle["status"] == "idle"
    assert idle["target"] is None

    # 2. Start running
    active_mission_tracker.start(
        target="target.test",
        provider_name="local",
        active_permitted=True,
        max_iterations=5,
        start_iteration=1,
        auto_approve=False,
    )
    running = active_mission_tracker.get_status()
    assert running["is_running"] is True
    assert running["status"] == "running"
    assert running["target"] == "target.test"
    assert running["provider_name"] == "local"
    assert running["max_iterations"] == 5
    assert running["current_iteration"] == 1
    assert running["elapsed_seconds"] >= 0
    assert running["last_progress"] is not None
    assert running["last_progress"]["state"] == "initializing"
    assert running["last_progress"]["message"] == "Initializing mission context..."

    # 3. Update progress (reasoning)
    active_mission_tracker.update_progress({
        "state": "reasoning",
        "target": "target.test",
        "iteration": 2,
        "max_iterations": 5,
        "provider": "local",
        "message": "Reasoning with local AI...",
    })
    prog = active_mission_tracker.get_status()
    assert prog["is_running"] is True
    assert prog["current_iteration"] == 2
    assert prog["last_progress"]["state"] == "reasoning"

    # 4. Paused for approval
    active_mission_tracker.pause({
        "status": "paused_for_approval",
        "pending_step": {"name": "SQLMap Scan", "tool": "sqlmap"},
        "action_id": "ACT-123",
    })
    paused = active_mission_tracker.get_status()
    assert paused["is_running"] is False
    assert paused["status"] == "paused_for_approval"
    assert paused["pending_approval"]["action_id"] == "ACT-123"

    # 5. Completed
    active_mission_tracker.complete({
        "status": "complete",
        "reason": "no_remaining_candidates",
    })
    completed = active_mission_tracker.get_status()
    assert completed["is_running"] is False
    assert completed["status"] == "completed"
    assert completed["result"]["status"] == "complete"

    # Cleanup
    active_mission_tracker.reset()


def test_autonomous_status_endpoint_returns_real_time_state():
    """Verify GET /api/v1/ai/autonomous-status exposes authoritative tracker state."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.ai.tracker import active_mission_tracker

    active_mission_tracker.reset()
    app = create_app()
    token = get_or_create_api_token()
    client = TestClient(app)

    # 1. Idle state
    resp = client.get("/api/v1/ai/autonomous-status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["is_running"] is False
    assert data["status"] == "idle"

    # 2. Running state
    active_mission_tracker.start(
        target="example.com",
        provider_name="ollama/qwen2.5-coder:7b",
        active_permitted=True,
        max_iterations=10,
        start_iteration=2,
        auto_approve=True,
    )
    resp_init = client.get("/api/v1/ai/autonomous-status", headers={"Authorization": f"Bearer {token}"})
    assert resp_init.status_code == 200
    init_data = resp_init.json()["data"]
    assert init_data["is_running"] is True
    assert init_data["last_progress"] is not None
    assert init_data["last_progress"]["state"] == "initializing"
    assert init_data["last_progress"]["message"] == "Initializing mission context..."

    active_mission_tracker.update_progress({
        "state": "executing",
        "target": "example.com",
        "iteration": 2,
        "max_iterations": 10,
        "tool": "nuclei",
        "message": "Executing nuclei scan",
        "auto_approved": True,
    })
    resp = client.get("/api/v1/ai/autonomous-status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["is_running"] is True
    assert data["status"] == "running"
    assert data["target"] == "example.com"
    assert data["auto_approve"] is True
    assert data["last_progress"]["tool"] == "nuclei"

    # 3. Paused state
    active_mission_tracker.pause({
        "status": "paused_for_approval",
        "action_id": "ACT-999",
        "pending_step": {"name": "Run sqlmap", "tool": "sqlmap"},
    })
    resp = client.get("/api/v1/ai/autonomous-status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["is_running"] is False
    assert data["status"] == "paused_for_approval"
    assert data["pending_approval"]["action_id"] == "ACT-999"

    # Reset tracker after test
    active_mission_tracker.reset()


def test_autonomous_loop_updates_tracker_on_pause(tmp_path: Path):
    """Verify planner.run_autonomous_loop properly populates active_mission_tracker when pausing for approval."""
    from unittest.mock import patch
    import json
    from nyx.ai.planner import MissionPlanner
    from nyx.ai.tracker import active_mission_tracker

    active_mission_tracker.reset()

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: example.com\nscope:\n  - example.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nmode: testing\nscope:\n  - example.com\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps([{"url": "https://example.com/login", "host": "example.com"}]), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps({"web": ["express"]}), encoding="utf-8")

    destructive_step = {
        "step": 1,
        "name": "SQLMap Active Injection Scan",
        "tool": "sqlmap",
        "action": "active_validation",
        "target": "https://example.com/api/user?id=1",
        "impact_class": "DESTRUCTIVE",
        "impact_justification": "Active SQL injection fuzzing modifies database state.",
        "reason": "SQL_INJECTION",
    }

    planner = MissionPlanner(base_dir=tmp_path)

    with patch.object(planner, "_select_steps", return_value=[destructive_step]), \
         patch.object(planner.ai_manager, "analyze", return_value={"selected_index": 0, "decision": "proceed", "reasoning": "Execute active validation"}):

        res = planner.run_autonomous_loop(
            target="example.com",
            active_permitted=True,
            max_iterations=1,
        )

        assert res.get("status") == "paused_for_approval"
        
        # Verify tracker was updated
        tracker_status = active_mission_tracker.get_status()
        assert tracker_status["is_running"] is False
        assert tracker_status["status"] == "paused_for_approval"
        assert tracker_status["target"] == "example.com"
        assert tracker_status["pending_approval"] is not None
        assert tracker_status["pending_approval"]["action_id"] == res.get("action_id")

    active_mission_tracker.reset()


def test_tab_switch_rehydration_scenario():
    """Simulate the reported tab switch scenario:
    1. Mission is executing in the background.
    2. Component unmounts (local state destroyed to idle).
    3. Component remounts and queries GET /api/v1/ai/autonomous-status.
    4. Proves state is fully restored: isRunning=True, progressData preserved, elapsedSeconds > 0, autoApprove=True.
    """
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.ai.tracker import active_mission_tracker

    active_mission_tracker.reset()
    app = create_app()
    token = get_or_create_api_token()
    client = TestClient(app)

    # 1. Mission starts and executes step
    active_mission_tracker.start(
        target="staging.corp",
        provider_name="ollama/qwen2.5-coder:7b",
        active_permitted=True,
        max_iterations=10,
        start_iteration=2,
        auto_approve=True,
    )
    active_mission_tracker.update_progress({
        "state": "executing",
        "target": "staging.corp",
        "iteration": 2,
        "max_iterations": 10,
        "current_step_index": 2,
        "total_planned_steps": 5,
        "step_name": "Nuclei Vulnerability Scan",
        "tool": "nuclei",
        "action": "active_validation",
        "phase": "VALIDATION",
        "message": "Executing Nuclei Vulnerability Scan (nuclei)",
        "remaining_destructive_count": 3,
        "upcoming_pipeline": [
            {"name": "SQLMap Scan", "tool": "sqlmap", "impact_class": "DESTRUCTIVE"}
        ],
        "auto_approved": True,
    })

    # 2. Operator switches away from tab (component unmounts, local state destroyed)
    ui_local_state = {
        "isRunning": False,
        "progressData": None,
        "elapsedSeconds": 0,
        "autoApprove": False,
    }
    assert ui_local_state["isRunning"] is False
    assert ui_local_state["progressData"] is None

    # 3. Operator switches back to tab (component remounts, calls loadMission -> GET /api/v1/ai/autonomous-status)
    resp = client.get("/api/v1/ai/autonomous-status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    backend_status = resp.json()["data"]

    # 4. Frontend re-hydration logic
    if backend_status["is_running"]:
        ui_local_state["isRunning"] = True
        ui_local_state["progressData"] = backend_status["last_progress"]
        ui_local_state["elapsedSeconds"] = backend_status["elapsed_seconds"]
        ui_local_state["autoApprove"] = backend_status["auto_approve"]

    # 5. Verify UI state is authoritatively restored
    assert ui_local_state["isRunning"] is True
    assert ui_local_state["progressData"] is not None
    assert ui_local_state["progressData"]["step_name"] == "Nuclei Vulnerability Scan"
    assert ui_local_state["progressData"]["tool"] == "nuclei"
    assert ui_local_state["autoApprove"] is True
    assert ui_local_state["elapsedSeconds"] >= 0

    active_mission_tracker.reset()


def test_nyx_mock_llm_deterministic_responses(monkeypatch):
    """Verify that when NYX_MOCK_LLM=1, LocalLlamaProvider returns deterministic, varied structured responses without network I/O."""
    from nyx.ai.providers.local_llama import LocalLlamaProvider
    import json

    monkeypatch.setenv("NYX_MOCK_LLM", "1")
    # Point to an unroutable/dead port to prove zero network requests are attempted
    prov = LocalLlamaProvider(endpoint_url="http://127.0.0.1:59999/api/generate", health_url="http://127.0.0.1:59999/api/tags")

    # 1. Ping / health check probe
    assert prov.generate("Say OK if you can read this.") == "OK. Connection verified."

    # 2. Candidate step decision
    cand_resp = prov.generate("Policy-Validated Candidate Steps: [{'name': 'SQLi'}]")
    cand_data = json.loads(cand_resp)
    assert cand_data["selected_index"] == 0
    assert cand_data["decision"] == "proceed"
    assert "SQL injection" in cand_data["reasoning"]

    # 3. Traversal / LFI step decision
    lfi_resp = prov.generate("Policy-Validated Candidate Steps: [{'name': 'LFI check'}]")
    lfi_data = json.loads(lfi_resp)
    assert lfi_data["selected_index"] == 0
    assert "traversal" in lfi_data["reasoning"]

    # 4. Context analysis / create_plan prompt
    plan_resp = prov.generate("tailored hypothesis for target: api.example.com, detected technologies: ['PHP', 'MySQL'], SQL Injection")
    plan_data = json.loads(plan_resp)
    assert "SQL" in plan_data["focus"]
    assert "SQL" in plan_data["reasoning"]

    # 5. Finding hypothesis description enrichment
    hypo_resp = prov.generate("You are a senior security researcher analyzing a detected web attack surface hypothesis for NYX. ### Why This Was Flagged")
    assert "### Why This Was Flagged" in hypo_resp
    assert "### Exploitability Conditions" in hypo_resp
    assert "### Verification Steps" in hypo_resp
    assert "### Status" in hypo_resp

    # 6. Finding evidence review
    ev_resp = prov.generate("VERDICT: review the evidence collected for finding")
    assert "VERDICT: CONFIRMED" in ev_resp

    # 7. analyze() integration
    res = prov.analyze({"target": "test.local", "technologies": ["express"]}, prompt="Select candidate step")
    assert res["status"] == "success"
    assert res["selected_index"] == 0
    assert res["decision"] == "proceed"

    # 8. test_connection() mock fast-path
    conn = prov.test_connection()
    assert conn["success"] is True
    assert conn["status"] == "ready"


def test_nyx_mock_llm_respects_explicit_requests_patch(monkeypatch):
    """Verify that when a test explicitly mocks requests.post, NYX_MOCK_LLM does NOT bypass the test's mock."""
    from unittest.mock import patch, MagicMock
    from nyx.ai.providers.local_llama import LocalLlamaProvider

    monkeypatch.setenv("NYX_MOCK_LLM", "1")
    prov = LocalLlamaProvider(endpoint_url="http://mock-ollama:11434/api/generate")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "Custom test mock output from patched requests.post"}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        res = prov.generate("Any prompt")
        assert res == "Custom test mock output from patched requests.post"
        assert mock_post.called


def test_concurrent_autonomous_mission_rejection():
    """Verify that triggering an autonomous run while a mission is already running returns HTTP 409 Conflict."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.ai.tracker import active_mission_tracker

    app = create_app()
    client = TestClient(app)
    token = get_or_create_api_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate an active running mission in the tracker
    active_mission_tracker.start(target="busy.target.com", provider_name="local")
    try:
        resp = client.post(
            "/api/v1/ai/autonomous-run",
            json={"target": "another.target.com", "max_iterations": 1},
            headers=headers,
        )
        assert resp.status_code == 409
        err = resp.json()["detail"]
        assert err["code"] == "MISSION_ALREADY_RUNNING"
        assert "busy.target.com" in err["message"]
    finally:
        active_mission_tracker.reset()


def test_autonomous_loop_emits_completion_event(tmp_path: Path):
    """Verify autonomous loop emits completion event and updates tracker to completed."""
    from unittest.mock import patch, MagicMock
    from nyx.ai.tracker import active_mission_tracker
    from nyx.ai.planner import MissionPlanner

    active_mission_tracker.reset()
    planner = MissionPlanner(base_dir=tmp_path)

    emitted_events = []
    def fake_emit(event_type, data=None, mission_id=None):
        emitted_events.append({"event": event_type, "data": data, "mission_id": mission_id})

    # Mock context to avoid external network/LLM calls
    with patch("nyx.web.events.emit_event_sync", side_effect=fake_emit), \
         patch.object(planner.context_engine, "get_target_context", return_value={"in_scope": True, "endpoints": ["https://target.local/api"]}), \
         patch.object(planner, "_select_steps", return_value=[]):

        res = planner.run_autonomous_loop(target="target.local", max_iterations=2)
        assert res["status"] == "complete"
        assert res["reason"] == "no_remaining_candidates"

        # Check tracker state
        st = active_mission_tracker.get_status()
        assert st["is_running"] is False
        assert st["status"] == "completed"
        assert st["result"] is not None
        assert st["result"]["status"] == "complete"

        # Check emitted completion events
        event_types = [e["event"] for e in emitted_events]
        assert "mission_completed" in event_types
        comp = next(e for e in emitted_events if e["event"] == "mission_completed")
        assert comp["data"]["state"] == "completed"
        assert comp["data"]["target"] == "target.local"
        assert comp["data"]["reason"] == "no_remaining_candidates"

    active_mission_tracker.reset()


def test_classification_sub_step_progress_emitted(tmp_path):
    """Verify that during classification, granular sub-step progress events are emitted to tracker and WebSocket."""
    from nyx.ai.tracker import active_mission_tracker
    from nyx.ai.planner import MissionPlanner
    from unittest.mock import patch

    active_mission_tracker.reset()
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "findings").mkdir(parents=True, exist_ok=True)

    active_mission_tracker.start(
        target="http://test.local",
        provider_name="mock",
        active_permitted=False,
        max_iterations=5,
    )

    planner = MissionPlanner(base_dir=tmp_path)

    emitted_progress = []
    def fake_emit(event_type, data=None, mission_id=None):
        if event_type == "mission_progress":
            emitted_progress.append(data)

    classified_sample = [
        {
            "url": "http://test.local/admin",
            "category": "AUTH",
            "skills": ["hunt-auth-bypass"],
            "matches": {},
        },
        {
            "url": "http://test.local/graphql",
            "category": "API",
            "skills": ["hunt-graphql"],
            "matches": {},
        },
    ]

    with patch("nyx.web.events.emit_event_sync", side_effect=fake_emit), \
         patch.object(planner.ai_manager, "generate", return_value="### Why This Was Flagged\nTest rationale\n### Exploitability Conditions\nNone\n### Verification Steps\nCheck\n### Status\nUnconfirmed"):

        created = planner._map_classification_to_hypotheses(
            classified_results=classified_sample,
            target="http://test.local",
        )

        assert len(created) >= 1
        assert len(emitted_progress) >= 1

        # Check latest tracker progress
        tracker_st = active_mission_tracker.get_status()
        last_prog = tracker_st.get("last_progress", {})
        assert "sub_step" in last_prog
        assert last_prog["sub_step"]["type"] == "hypothesis_enrichment"
        assert last_prog["sub_step"]["current"] >= 1
        assert last_prog["sub_step"]["total"] >= 1
        assert "Enriching hypothesis" in last_prog["message"]

        # Check emitted WS events
        enrich_events = [p for p in emitted_progress if p.get("sub_step", {}).get("type") == "hypothesis_enrichment"]
        assert len(enrich_events) >= 1
        first_enrich = enrich_events[0]
        assert "Enriching hypothesis" in first_enrich["message"]
        assert first_enrich["sub_step"]["current"] == 1

    active_mission_tracker.reset()


def test_shutdown_event_coordinator_and_signal_handling():
    """Verify thread-safe shutdown coordinator and second-Ctrl+C force-quit mechanics."""
    from nyx.infrastructure.process import (
        is_shutdown_requested,
        request_shutdown,
        reset_shutdown,
    )

    reset_shutdown()
    try:
        assert is_shutdown_requested() is False

        request_shutdown()
        assert is_shutdown_requested() is True

        # Idempotent
        request_shutdown()
        assert is_shutdown_requested() is True

        reset_shutdown()
        assert is_shutdown_requested() is False
    finally:
        reset_shutdown()


def test_autonomous_loop_aborts_on_shutdown_request(tmp_path, monkeypatch):
    """Verify autonomous loop and bg worker gracefully abort when shutdown is requested."""
    from nyx.infrastructure.process import (
        is_shutdown_requested,
        request_shutdown,
        reset_shutdown,
    )
    from nyx.ai.planner import MissionPlanner
    from nyx.ai.tracker import active_mission_tracker

    reset_shutdown()
    active_mission_tracker.reset()

    try:
        # Setup engagement target
        eng_dir = tmp_path / ".engagement"
        eng_dir.mkdir(parents=True, exist_ok=True)
        (eng_dir / "target.yaml").write_text("scope:\n  - auto.target.com\n", encoding="utf-8")
        (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
        (eng_dir / "endpoints.json").write_text('[{"url": "https://auto.target.com/api"}]', encoding="utf-8")

        planner = MissionPlanner(base_dir=tmp_path)
        planner._select_steps = lambda ctx: [{
            "step": 1,
            "name": "Passive Port Scan",
            "action": "scan",
            "tool": "nmap",
            "description": "Port scan.",
            "impact_class": "RECON",
            "policy_status": "POLICY_COMPLIANT",
        }]

        # 1. Shutdown requested before loop starts
        request_shutdown()
        res = planner.run_autonomous_loop("auto.target.com", max_iterations=3)
        assert res["status"] == "aborted"
        assert res["reason"] == "shutdown_requested"
        assert active_mission_tracker.is_running is False
        assert active_mission_tracker.status == "aborted"

        # 2. Shutdown requested mid-iteration (e.g. during AI analyze)
        reset_shutdown()
        active_mission_tracker.reset()

        def analyze_and_shutdown(*args, **kwargs):
            request_shutdown()
            return {"selected_index": 0, "reasoning": "Selected"}

        planner.ai_manager.analyze = analyze_and_shutdown
        res2 = planner.run_autonomous_loop("auto.target.com", max_iterations=3)
        assert res2["status"] == "aborted"
        assert res2["reason"] == "shutdown_requested"
        assert active_mission_tracker.is_running is False
        assert active_mission_tracker.status == "aborted"
    finally:
        reset_shutdown()
        active_mission_tracker.reset()


def test_run_cmd_refuses_execution_during_shutdown():
    """Verify run_cmd refuses to spawn new processes once shutdown is requested."""
    from nyx.infrastructure.process import (
        run_cmd,
        request_shutdown,
        reset_shutdown,
    )

    reset_shutdown()
    try:
        # Before shutdown
        rc, out, err = run_cmd(["echo", "nyx-shutdown-test"])
        # Echo should work or return standard code
        assert rc in (0, 127)  # 127 if echo isn't binary on windows, 0 if it is or handled

        # Trigger shutdown
        request_shutdown()
        rc_shut, out_shut, err_shut = run_cmd(["echo", "should-not-spawn"])
        assert rc_shut == 130
        assert "system shutdown in progress" in err_shut
    finally:
        reset_shutdown()


def test_autonomous_run_route_handles_cancellation(monkeypatch):
    """Verify run_ai_autonomous_loop route traps CancelledError and aborts cleanly."""
    import asyncio
    from nyx.web.routes.intelligence import run_ai_autonomous_loop, AIAutonomousRequest
    from nyx.ai.tracker import active_mission_tracker
    from nyx.infrastructure.process import is_shutdown_requested, reset_shutdown

    reset_shutdown()
    active_mission_tracker.reset()

    class FakeService:
        class FakePlanner:
            def run_autonomous_loop(self, *args, **kwargs):
                pass
        planner = FakePlanner()

    # Mock asyncio.to_thread to raise CancelledError
    async def mock_to_thread(*args, **kwargs):
        raise asyncio.CancelledError()

    monkeypatch.setattr(asyncio, "to_thread", mock_to_thread)

    async def _run():
        req = AIAutonomousRequest(target="test.example.com")
        res = await run_ai_autonomous_loop(req=req, service=FakeService())
        assert res["status"] == "aborted"
        assert res["reason"] == "cancelled"
        assert is_shutdown_requested() is True
        assert active_mission_tracker.is_running is False
        assert active_mission_tracker.status == "aborted"

    try:
        asyncio.run(_run())
    finally:
        reset_shutdown()
        active_mission_tracker.reset()


def test_recon_service_and_surface_routes_target_scoping(tmp_path):
    """Verify get_endpoints and get_assets default to active target and isolate cross-target assets."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.application.recon_service import ReconService

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target:\n  name: http://localhost:4444/#/\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    mixed_endpoints = [
        {"url": "https://static.tesla.com/login", "host": "static.tesla.com"},
        {"url": "https://api.tesla.com/v1/user", "host": "api.tesla.com"},
        {"url": "http://localhost:4444/api/v1/test", "host": "localhost"},
        {"url": "http://localhost:4444/admin", "host": "localhost"},
    ]
    (eng_dir / "endpoints.json").write_text(json.dumps(mixed_endpoints), encoding="utf-8")

    # 1. ReconService.get_endpoints with no target defaults to active target
    svc = ReconService(base_dir=tmp_path)
    res_default = svc.get_endpoints()
    urls_default = [ep["url"] for ep in res_default["endpoints"]]
    assert len(urls_default) == 2
    assert "http://localhost:4444/api/v1/test" in urls_default
    assert not any("tesla.com" in u for u in urls_default)

    # 2. ReconService.get_endpoints with explicit target
    res_tesla = svc.get_endpoints(target="tesla.com")
    urls_tesla = [ep["url"] for ep in res_tesla["endpoints"]]
    assert len(urls_tesla) == 2
    assert "https://static.tesla.com/login" in urls_tesla
    assert not any("localhost" in u for u in urls_tesla)

    # 3. HTTP API routes test
    import os
    orig_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        app = create_app()
        client = TestClient(app)
        token = get_or_create_api_token()
        headers = {"Authorization": f"Bearer {token}"}

        # GET /api/v1/endpoints (no target param)
        resp_ep = client.get("/api/v1/endpoints", headers=headers)
        assert resp_ep.status_code == 200
        ep_data = resp_ep.json().get("endpoints", [])
        assert len(ep_data) == 2
        assert all("localhost" in ep["url"] for ep in ep_data)

        # GET /api/v1/assets (no target param)
        resp_assets = client.get("/api/v1/assets", headers=headers)
        assert resp_assets.status_code == 200
        assert resp_assets.json().get("data", {}).get("endpoints_count") == 2
    finally:
        os.chdir(orig_cwd)


def test_findings_and_approvals_target_scoping(tmp_path):
    """Verify list_findings and get_pending_approvals default to active target and isolate data."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.core import findings as core_findings

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target:\n  name: http://localhost:4444/#/\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    mixed_findings = [
        {"id": "FH-2026-001", "target": "tesla.com", "endpoint": "https://static.tesla.com/login", "title": "Tesla Reflected XSS", "status": "OPEN", "severity": "High"},
        {"id": "FH-2026-002", "target": "http://localhost:4444", "endpoint": "http://localhost:4444/api/v1/user", "title": "Localhost IDOR", "status": "OPEN", "severity": "High"},
    ]
    (eng_dir / "findings.json").write_text(json.dumps(mixed_findings), encoding="utf-8")

    # 1. core_findings.list_findings with no target defaults to active target
    f_res = core_findings.list_findings(base_dir=tmp_path)
    f_list = f_res.get("findings", [])
    assert len(f_list) == 1
    assert f_list[0]["id"] == "FH-2026-002"

    # 2. HTTP route GET /api/v1/findings defaults to active target
    import os
    orig_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        app = create_app()
        client = TestClient(app)
        token = get_or_create_api_token()
        headers = {"Authorization": f"Bearer {token}"}

        resp_f = client.get("/api/v1/findings", headers=headers)
        assert resp_f.status_code == 200
        findings_data = resp_f.json().get("findings", [])
        assert len(findings_data) == 1
        assert findings_data[0]["id"] == "FH-2026-002"

        # Explicit target query
        resp_tesla = client.get("/api/v1/findings?target=tesla.com", headers=headers)
        assert resp_tesla.status_code == 200
        tesla_data = resp_tesla.json().get("findings", [])
        assert len(tesla_data) == 1
        assert tesla_data[0]["id"] == "FH-2026-001"
    finally:
        os.chdir(orig_cwd)


def test_execution_and_continuous_target_scoping(tmp_path):
    """Verify execution history and continuous routes isolate cross-target data."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.application.execution_service import ExecutionService
    from nyx.intelligence.history import AssetHistory

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    db_dir = eng_dir / "database"
    db_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target:\n  name: http://localhost:4444/#/\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    # 1. Execution history
    mixed_execs = [
        {"execution_id": "EXEC-1", "tool": "nuclei", "target": "https://static.tesla.com", "status": "COMPLETED"},
        {"execution_id": "EXEC-2", "tool": "sqlmap", "target": "http://localhost:4444/api/v1/user", "status": "COMPLETED"},
    ]
    (db_dir / "executions.json").write_text(json.dumps(mixed_execs), encoding="utf-8")

    exec_svc = ExecutionService(base_dir=tmp_path)
    res_default = exec_svc.get_history()
    h_default = res_default.data.get("history", [])
    assert len(h_default) == 1
    assert h_default[0]["execution_id"] == "EXEC-2"

    res_tesla = exec_svc.get_history(target="tesla.com")
    h_tesla = res_tesla.data.get("history", [])
    assert len(h_tesla) == 1
    assert h_tesla[0]["execution_id"] == "EXEC-1"

    # 2. Asset history snapshots
    mixed_snapshots = [
        {"target": "tesla.com", "timestamp": "2026-09-01T00:00:00", "graph": {}},
        {"target": "http://localhost:4444", "timestamp": "2026-09-02T00:00:00", "graph": {}},
    ]
    (db_dir / "asset_history.json").write_text(json.dumps(mixed_snapshots), encoding="utf-8")

    history_mod = AssetHistory(base_dir=tmp_path)
    snaps_loc = history_mod.get_snapshots(target="http://localhost:4444/#/")
    assert len(snaps_loc) == 1
    assert snaps_loc[0]["target"] == "http://localhost:4444"

    snaps_tesla = history_mod.get_snapshots(target="tesla.com")
    assert len(snaps_tesla) == 1
    assert snaps_tesla[0]["target"] == "tesla.com"

    # 3. HTTP routes test
    import os
    orig_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        app = create_app()
        client = TestClient(app)
        token = get_or_create_api_token()
        headers = {"Authorization": f"Bearer {token}"}

        # GET /api/v1/execution/history without target param
        resp_ex = client.get("/api/v1/execution/history", headers=headers)
        assert resp_ex.status_code == 200
        ex_list = resp_ex.json().get("data", {}).get("history", [])
        assert len(ex_list) == 1
        assert ex_list[0]["execution_id"] == "EXEC-2"

        # GET /api/v1/execution/history with target param
        resp_ex_t = client.get("/api/v1/execution/history?target=tesla.com", headers=headers)
        assert resp_ex_t.status_code == 200
        ex_list_t = resp_ex_t.json().get("data", {}).get("history", [])
        assert len(ex_list_t) == 1
        assert ex_list_t[0]["execution_id"] == "EXEC-1"
    finally:
        os.chdir(orig_cwd)


def test_background_recon_target_switch_isolation(tmp_path):
    """Verify background recon for another target does not pollute endpoints when target is switched."""
    from nyx.core.recon import sync_recon_to_engagement
    from nyx.application.recon_service import ReconService
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target:\n  name: http://localhost:4444/#/\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nscope:\n  - http://localhost:4444\n", encoding="utf-8")

    # Seed with 90 localhost endpoints
    localhost_eps = [
        {"url": f"http://localhost:4444/api/v1/resource_{i}", "host": "localhost", "status": 200, "source": "crawler"}
        for i in range(90)
    ]
    (eng_dir / "endpoints.json").write_text(json.dumps(localhost_eps), encoding="utf-8")

    # Background recon for tesla.com completes AFTER target has switched to localhost
    res = sync_recon_to_engagement(
        target="tesla.com",
        subs={"static.tesla.com", "api.tesla.com"},
        resolved={"static.tesla.com": ["1.2.3.4"]},
        live=[{"url": "https://static.tesla.com/login", "host": "static.tesla.com", "code": 200}],
        base_dir=tmp_path,
    )
    # Recon should be discarded due to scope/target mismatch
    assert res == (0, 0, 0)

    # Verify ReconService.get_endpoints returns only 90 localhost endpoints
    svc = ReconService(base_dir=tmp_path)
    endpoints_res = svc.get_endpoints()
    eps = endpoints_res.get("endpoints", [])
    assert len(eps) == 90
    assert all("localhost" in ep["url"] for ep in eps)
    assert not any("tesla.com" in ep["url"] for ep in eps)

    # Verify HTTP route returns only 90 localhost endpoints
    import os
    orig_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        app = create_app()
        client = TestClient(app)
        token = get_or_create_api_token()
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.get("/api/v1/endpoints", headers=headers)
        assert resp.status_code == 200
        data = resp.json().get("endpoints", [])
        assert len(data) == 90
        assert all("localhost" in ep["url"] for ep in data)
        assert not any("tesla.com" in ep["url"] for ep in data)
    finally:
        os.chdir(orig_cwd)


def test_engine_status_target_scoping(tmp_path):
    """Verify GET /api/v1/engine/status reports findings and approvals scoped to active target."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target:\n  name: http://localhost:4444/#/\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nscope:\n  - http://localhost:4444\n", encoding="utf-8")

    mixed_findings = [
        {"id": f"FH-TESLA-{i}", "target": "tesla.com", "endpoint": "https://static.tesla.com/login", "title": "Tesla XSS", "status": "OPEN", "severity": "High", "evidence_ids": ["EV-1"]}
        for i in range(5)
    ]
    mixed_findings.append(
        {"id": "FH-LOCAL-001", "target": "http://localhost:4444", "endpoint": "http://localhost:4444/api/v1/user", "title": "Local IDOR", "status": "OPEN", "severity": "High", "evidence_ids": ["EV-2"]}
    )
    (eng_dir / "findings.json").write_text(json.dumps(mixed_findings), encoding="utf-8")

    import os
    orig_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        app = create_app()
        client = TestClient(app)
        token = get_or_create_api_token()
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.get("/api/v1/engine/status", headers=headers)
        assert resp.status_code == 200
        res_data = resp.json().get("data", {})
        assert res_data.get("engine", {}).get("target") == "http://localhost:4444/#/"
        # Findings count must be 1 for localhost, not 6
        assert res_data.get("vault", {}).get("findings_count") == 1
        assert res_data.get("vault", {}).get("evidence_count") == 1
    finally:
        os.chdir(orig_cwd)


def test_active_recon_tracker_lifecycle():
    """Verify ActiveReconTracker tracks real-time reconnaissance lifecycle stages and enforces target isolation."""
    from nyx.recon.tracker import active_recon_tracker
    active_recon_tracker.reset()

    # 1. Idle state
    idle = active_recon_tracker.get_status()
    assert idle["is_running"] is False
    assert idle["status"] == "idle"
    assert idle["target"] is None

    # 2. Start recon
    active_recon_tracker.start(target="http://localhost:4444/#/")
    running = active_recon_tracker.get_status()
    assert running["is_running"] is True
    assert running["status"] == "running"
    assert running["target"] == "http://localhost:4444/#/"
    assert running["current_phase"] == "subdomain_enum"
    assert running["elapsed_seconds"] >= 0

    # 3. Update phases
    active_recon_tracker.update_phase("dns_resolution", "Resolving DNS for 5 subdomains...", subdomains_count=5)
    p1 = active_recon_tracker.get_status()
    assert p1["current_phase"] == "dns_resolution"
    assert p1["progress"]["subdomains_count"] == 5

    active_recon_tracker.update_phase("http_probing", "Probing 4 HTTP hosts...", resolved_count=4)
    p2 = active_recon_tracker.get_status()
    assert p2["current_phase"] == "http_probing"
    assert p2["progress"]["resolved_count"] == 4

    # Target isolation check: querying for another target should report idle
    other_status = active_recon_tracker.get_status(target="tesla.com")
    assert other_status["is_running"] is False
    assert other_status["status"] == "idle"

    # Querying for matching target reports running
    matching_status = active_recon_tracker.get_status(target="http://localhost:4444")
    assert matching_status["is_running"] is True

    # 4. Complete
    active_recon_tracker.complete({"sync_total": 90, "sync_new": 10})
    done = active_recon_tracker.get_status()
    assert done["is_running"] is False
    assert done["status"] == "completed"
    assert done["result"]["sync_total"] == 90

    # 5. Fail
    active_recon_tracker.start(target="example.com")
    active_recon_tracker.fail("Connection refused")
    failed = active_recon_tracker.get_status()
    assert failed["is_running"] is False
    assert failed["status"] == "error"
    assert failed["error"] == "Connection refused"

    # Cleanup
    active_recon_tracker.reset()


def test_recon_status_endpoint_returns_real_time_state():
    """Verify GET /api/v1/surface/recon-status exposes authoritative tracker state over HTTP."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.recon.tracker import active_recon_tracker

    active_recon_tracker.reset()
    app = create_app()
    client = TestClient(app)
    token = get_or_create_api_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Idle state
    resp_idle = client.get("/api/v1/surface/recon-status", headers=headers)
    assert resp_idle.status_code == 200
    idle_data = resp_idle.json()["data"]
    assert idle_data["is_running"] is False
    assert idle_data["status"] == "idle"

    # 2. Running state
    active_recon_tracker.start(target="http://localhost:4444")
    active_recon_tracker.update_phase("http_probing", "Probing HTTP services...", live_count=12)

    resp_running = client.get("/api/v1/surface/recon-status?target=http://localhost:4444", headers=headers)
    assert resp_running.status_code == 200
    running_data = resp_running.json()["data"]
    assert running_data["is_running"] is True
    assert running_data["status"] == "running"
    assert running_data["current_phase"] == "http_probing"
    assert running_data["progress"]["live_count"] == 12

    # Different target queried returns idle
    resp_other = client.get("/api/v1/surface/recon-status?target=tesla.com", headers=headers)
    assert resp_other.status_code == 200
    assert resp_other.json()["data"]["is_running"] is False

    # Cleanup
    active_recon_tracker.reset()


def test_recon_mid_run_refresh_rehydration_state_trace(tmp_path):
    """Verify state trace: start recon, simulate browser refresh mid-run, confirm live progress is re-hydrated."""
    import time
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.web.auth import get_or_create_api_token
    from nyx.recon.tracker import active_recon_tracker

    active_recon_tracker.reset()
    app = create_app()
    client = TestClient(app)
    token = get_or_create_api_token()
    headers = {"Authorization": f"Bearer {token}"}

    target = "http://localhost:4444/#/"

    # T0: Initial state before click
    t0_resp = client.get(f"/api/v1/surface/recon-status?target={target}", headers=headers)
    assert t0_resp.status_code == 200
    t0_data = t0_resp.json()["data"]
    assert t0_data["is_running"] is False
    assert t0_data["status"] == "idle"

    # T1: Operator clicks "Run Recon" -> tracker starts
    active_recon_tracker.start(target=target)
    active_recon_tracker.update_phase("subdomain_enum", "Enumerating subdomains for localhost...")
    t1_resp = client.get(f"/api/v1/surface/recon-status?target={target}", headers=headers)
    t1_data = t1_resp.json()["data"]
    assert t1_data["is_running"] is True
    assert t1_data["current_phase"] == "subdomain_enum"

    # T2: Recon advances to DNS resolution and HTTP probing
    time.sleep(0.05)
    active_recon_tracker.update_phase("dns_resolution", "Resolving DNS for 1 subdomains...", subdomains_count=1)
    active_recon_tracker.update_phase("http_probing", "Probing HTTP services across 1 endpoints...", resolved_count=1)

    # T3: Operator presses browser REFRESH (F5) or switches tabs mid-run!
    # Fresh mount queries recon-status independently
    refresh_client = TestClient(app)  # Simulate fresh browser session mount
    t3_resp = refresh_client.get(f"/api/v1/surface/recon-status?target={target}", headers=headers)
    assert t3_resp.status_code == 200
    t3_data = t3_resp.json()["data"]

    # CONFIRM RE-HYDRATION: UI does NOT show idle; it recovers live running state!
    assert t3_data["is_running"] is True
    assert t3_data["status"] == "running"
    assert t3_data["target"] == target
    assert t3_data["current_phase"] == "http_probing"
    assert "Probing HTTP services" in t3_data["phase_message"]
    assert t3_data["progress"]["resolved_count"] == 1
    assert t3_data["elapsed_seconds"] >= 0.05

    # T4: Recon finishes content discovery & engagement syncing
    active_recon_tracker.update_phase("content_discovery", "Mapping routes and parameters...")
    active_recon_tracker.update_phase("syncing", "Syncing 90 discovered assets into memory...")
    active_recon_tracker.complete({
        "status": "success",
        "target": target,
        "sync_total": 90,
        "sync_new": 90,
        "sync_known": 0,
    })

    # T5: Post-completion polling queries status
    t5_resp = refresh_client.get(f"/api/v1/surface/recon-status?target={target}", headers=headers)
    assert t5_resp.status_code == 200
    t5_data = t5_resp.json()["data"]
    assert t5_data["is_running"] is False
    assert t5_data["status"] == "completed"
    assert t5_data["result"]["sync_total"] == 90

    # Cleanup
    active_recon_tracker.reset()









