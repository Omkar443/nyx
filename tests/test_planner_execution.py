import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from nyx.ai.planner import MissionPlanner
from nyx.application.finding_service import FindingService


def test_execute_plan_no_simulated_and_triage_skipped(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    
    # Initialize basic engagement
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: test.vulnweb.com\nscope:\n  - test.vulnweb.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    
    planner = MissionPlanner(base_dir=tmp_path)
    
    plan = {
        "target": "http://test.vulnweb.com",
        "steps": [
            {
                "step": 1,
                "name": "Technology Fingerprinting",
                "action": "passive_recon",
                "tool": "httpx",
                "permitted": True,
            },
            {
                "step": 2,
                "name": "Endpoint & Parameter Harvesting",
                "action": "endpoint_harvesting",
                "tool": "katana",
                "permitted": True,
            },
            {
                "step": 3,
                "name": "Attack Surface Mapping & Skill Matching",
                "action": "technology_mapping",
                "tool": "nyx-classify",
                "permitted": True,
            },
            {
                "step": 4,
                "name": "Controlled Vulnerability Triage",
                "action": "finding_triage",
                "tool": "nyx-triage",
                "permitted": True,
            },
        ],
    }
    
    res = planner.execute_plan(plan)
    assert res["status"] == "success"
    assert res["executed_steps"] == 4
    
    # 1. Assert NO step has "simulated": True
    for step_res in res["step_results"]:
        step_result_dict = step_res["result"]
        assert "simulated" not in step_result_dict or step_result_dict.get("simulated") is not True
    
    # 2. Assert step 3 (nyx-classify) returns real classification
    classify_step = res["step_results"][2]
    assert classify_step["name"] == "Attack Surface Mapping & Skill Matching"
    assert classify_step["result"]["status"] == "success"
    assert "skills" in classify_step["result"]
    assert "category" in classify_step["result"]
    
    # 3. Assert step 4 (nyx-triage) executes triage on created hypotheses or skips when zero findings
    triage_step = res["step_results"][3]
    assert triage_step["name"] == "Controlled Vulnerability Triage"
    assert triage_step["result"]["status"] in ("skipped", "success")


def test_execute_plan_with_pending_finding(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    
    # Initialize basic engagement
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: test.vulnweb.com\nscope:\n  - test.vulnweb.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    
    # Create a finding in state HYPOTHESIS
    finding_svc = FindingService(base_dir=tmp_path)
    f_res = finding_svc.create(
        title="Reflected XSS on search",
        endpoint="http://test.vulnweb.com/search.aspx",
        parameter="query",
        vulnerability="Cross-Site Scripting",
        severity="High",
        description="Empirical HTTP request evidence shows reflected payload.",
        target="test.vulnweb.com",
    )
    assert f_res["status"] == "success"
    
    planner = MissionPlanner(base_dir=tmp_path)
    plan = {
        "target": "http://test.vulnweb.com",
        "steps": [
            {
                "step": 1,
                "name": "Controlled Vulnerability Triage",
                "action": "finding_triage",
                "tool": "nyx-triage",
                "permitted": True,
            },
        ],
    }
    
    res = planner.execute_plan(plan)
    assert res["status"] == "success"
    triage_step = res["step_results"][0]
    assert triage_step["result"]["status"] == "success"
    assert triage_step["result"]["triaged_count"] == 1
    assert len(triage_step["result"]["findings"]) == 1


def test_execute_plan_unknown_tool_raises_error(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: test.vulnweb.com\nscope:\n  - test.vulnweb.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    
    planner = MissionPlanner(base_dir=tmp_path)
    plan = {
        "target": "http://test.vulnweb.com",
        "steps": [
            {
                "step": 1,
                "name": "Unknown Tool Step",
                "action": "passive_recon",
                "tool": "nonexistent-tool",
                "permitted": True,
            },
        ],
    }
    
    with pytest.raises(ValueError, match="Unknown or unsupported tool 'nonexistent-tool'"):
        planner.execute_plan(plan)


def test_context_engine_phase_reads_state(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: test.vulnweb.com\nscope:\n  - test.vulnweb.com\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS", "mode": "RESEARCH"}), encoding="utf-8")

    from nyx.ai.context import ContextEngine
    ctx_engine = ContextEngine(base_dir=tmp_path)
    ctx = ctx_engine.get_target_context("test.vulnweb.com")
    assert ctx["phase"] == "ANALYSIS"


def test_ai_service_execute_mission(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: test.vulnweb.com\nscope:\n  - test.vulnweb.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS"}), encoding="utf-8")

    from nyx.application.ai_service import AIService
    svc = AIService(base_dir=tmp_path)
    res = svc.execute_mission("http://test.vulnweb.com")
    assert res.is_success
    assert res.data["executed_steps"] == 4


def test_cli_ai_execute_command(tmp_path: Path, monkeypatch, capsys):
    import argparse
    from nyx_cli.cli import cmd_ai

    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: test.vulnweb.com\nscope:\n  - test.vulnweb.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS"}), encoding="utf-8")

    args = argparse.Namespace(
        ai_subcommand="execute",
        target="http://test.vulnweb.com",
        active_permitted=False,
    )
    ret = cmd_ai(args)
    assert ret == 0
    captured = capsys.readouterr().out
    assert "NYX AI Mission Execution" in captured
    assert "Technology Fingerprinting" in captured
    assert "Attack Surface Mapping" in captured
    assert "Controlled Vulnerability Triage" in captured


def test_select_steps_four_combinations():
    planner = MissionPlanner()

    # Combination 1: (no endpoints, no hypothesis findings) -> all 4 steps
    ctx1 = {"endpoints": [], "findings": []}
    steps1 = planner._select_steps(ctx1)
    assert len(steps1) == 4
    assert [s["step"] for s in steps1] == [1, 2, 3, 4]
    assert [s["tool"] for s in steps1] == ["httpx", "katana", "nyx-classify", "nyx-triage"]

    # Combination 2: (has endpoints, no hypothesis findings) -> only step 3 survives, renumbered to step 1
    ctx2 = {"endpoints": ["http://example.com/api"], "findings": []}
    steps2 = planner._select_steps(ctx2)
    assert len(steps2) == 1
    assert steps2[0]["step"] == 1
    assert steps2[0]["tool"] == "nyx-classify"
    assert steps2[0]["name"] == "Attack Surface Mapping & Skill Matching"

    # Combination 3: (no endpoints, has hypothesis findings) -> all 4 steps (unaffected by findings signal since endpoints empty)
    ctx3 = {"endpoints": [], "findings": [{"state": "HYPOTHESIS"}]}
    steps3 = planner._select_steps(ctx3)
    assert len(steps3) == 4
    assert [s["step"] for s in steps3] == [1, 2, 3, 4]
    assert [s["tool"] for s in steps3] == ["httpx", "katana", "nyx-classify", "nyx-triage"]

    # Combination 4: (has endpoints, has hypothesis findings) -> steps 3 and 4 survive, renumbered to 1 and 2
    ctx4 = {
        "target": "example.com",
        "endpoints": ["http://example.com/api"],
        "findings": [{"state": "HYPOTHESIS", "target": "example.com", "endpoint": "http://example.com/api"}],
    }
    steps4 = planner._select_steps(ctx4)
    assert len(steps4) == 2
    assert [s["step"] for s in steps4] == [1, 2]
    assert [s["tool"] for s in steps4] == ["nyx-classify", "nyx-triage"]
    assert steps4[0]["name"] == "Attack Surface Mapping & Skill Matching"
    assert steps4[1]["name"] == "Controlled Vulnerability Triage"


def test_create_plan_with_existing_endpoints_and_no_findings(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: server.vulnapp.id\nscope:\n  - server.vulnapp.id\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS"}), encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps([{"url": "https://server.vulnapp.id/mutillidae/"}]), encoding="utf-8")
    (eng_dir / "findings.json").write_text("[]", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("https://server.vulnapp.id/mutillidae/")
    assert plan["valid"] is True
    assert plan["total_steps"] == 1
    assert len(plan["steps"]) == 1
    assert plan["steps"][0]["step"] == 1
    assert plan["steps"][0]["tool"] == "nyx-classify"
    assert plan["steps"][0]["name"] == "Attack Surface Mapping & Skill Matching"


def test_cli_ai_plan_with_provider_flag(tmp_path: Path, monkeypatch, capsys):
    import argparse
    from nyx_cli.cli import cmd_ai

    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: server.vulnapp.id\nscope:\n  - server.vulnapp.id\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS"}), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps(["PHP", "nginx"]), encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps([{"url": "https://server.vulnapp.id/index.php"}]), encoding="utf-8")

    args = argparse.Namespace(
        ai_subcommand="plan",
        target="server.vulnapp.id",
        provider="local",
    )
    with patch("nyx.ai.manager.AIManager.analyze", return_value={"analysis": "Mock analysis", "recommended_focus": "SQL Injection"}):
        ret = cmd_ai(args)
    assert ret == 0
    captured = capsys.readouterr().out
    assert "NYX Recommended AI Mission Plan" in captured
    assert "Provider:          local" in captured
    assert any(k in captured for k in ("Technology-Specific Attack Surface Mapping", "Attack Surface Mapping", "PHP & Web Server Attack Surface Analysis"))


def test_cli_ai_execute_with_provider_flag(tmp_path: Path, monkeypatch, capsys):
    import argparse
    from nyx_cli.cli import cmd_ai

    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: server.vulnapp.id\nscope:\n  - server.vulnapp.id\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS"}), encoding="utf-8")

    args = argparse.Namespace(
        ai_subcommand="execute",
        target="http://server.vulnapp.id",
        provider="local",
        active_permitted=False,
    )
    ret = cmd_ai(args)
    assert ret == 0
    captured = capsys.readouterr().out
    assert "NYX AI Mission Execution" in captured


def test_execute_plan_active_permitted_dry_run_toggling(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: test.vulnweb.com\nscope:\n  - test.vulnweb.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    plan = {
        "target": "http://test.vulnweb.com",
        "steps": [
            {
                "step": 1,
                "name": "Technology Fingerprinting",
                "action": "passive_recon",
                "tool": "httpx",
                "permitted": True,
            },
        ],
    }

    # 1. When active_permitted is False -> dry_run=True
    with patch("nyx.application.execution_service.ExecutionService.run_tool") as mock_run:
        mock_res = MagicMock()
        mock_res.to_dict.return_value = {"status": "success", "dry_run": True}
        mock_run.return_value = mock_res

        planner.execute_plan(plan, active_permitted=False)
        mock_run.assert_called_once_with("httpx", "http://test.vulnweb.com", arguments=None, dry_run=True, active_permitted=False)

    # 2. When active_permitted is True -> dry_run=False
    with patch("nyx.application.execution_service.ExecutionService.run_tool") as mock_run:
        mock_res = MagicMock()
        mock_res.to_dict.return_value = {"status": "success", "dry_run": False}
        mock_run.return_value = mock_res

        planner.execute_plan(plan, active_permitted=True)
        mock_run.assert_called_once_with("httpx", "http://test.vulnweb.com", arguments=None, dry_run=False, active_permitted=True)


def test_create_plan_out_of_scope_target_returns_error(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: server.vulnapp.id\nscope:\n  - server.vulnapp.id\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS"}), encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("wrong-target.com")

    assert plan["status"] == "error"
    assert plan["target"] == "wrong-target.com"
    assert "does not match the active engagement's scope" in plan["error"]
    assert "nyx engagement init wrong-target.com" in plan["error"]

    # Also verify validate_plan and execute_plan handle error plan cleanly
    valid, msg = planner.validate_plan(plan)
    assert valid is False
    assert "does not match the active engagement's scope" in msg

    exec_res = planner.execute_plan(plan)
    assert exec_res["status"] == "error"
    assert "does not match the active engagement's scope" in exec_res["error"]


def test_ai_service_scope_mismatch_returns_failure(tmp_path: Path, monkeypatch):
    from nyx.application.ai_service import AIService

    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: server.vulnapp.id\nscope:\n  - server.vulnapp.id\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS"}), encoding="utf-8")

    svc = AIService(base_dir=tmp_path)
    res_plan = svc.plan_mission("example.com")
    assert not res_plan.is_success
    assert "does not match the active engagement's scope" in res_plan.error

    res_exec = svc.execute_mission("example.com")
    assert not res_exec.is_success
    assert "does not match the active engagement's scope" in res_exec.error


def test_execute_plan_classify_with_real_context_endpoints(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: server.vulnapp.id\nscope:\n  - server.vulnapp.id\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS"}), encoding="utf-8")

    # Add realistic endpoints with paths and parameters that match URL patterns
    sample_endpoints = [
        {"url": "https://server.vulnapp.id/mutillidae/index.php?page=login.php&redirect=https://example.com"},
        {"url": "https://server.vulnapp.id/api/v1/user/123"},
        {"url": "https://server.vulnapp.id/upload/document.pdf"},
    ]
    (eng_dir / "endpoints.json").write_text(json.dumps(sample_endpoints), encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    plan = {
        "target": "server.vulnapp.id",
        "steps": [
            {
                "step": 1,
                "name": "Attack Surface Mapping & Skill Matching",
                "action": "technology_mapping",
                "tool": "nyx-classify",
                "permitted": True,
            },
        ],
    }

    res = planner.execute_plan(plan)
    assert res["status"] == "success"
    step_res = res["step_results"][0]["result"]
    assert step_res["status"] == "success"
    assert step_res["classified_count"] == 3
    assert len(step_res["results"]) == 3

    r0 = step_res["results"][0]
    assert r0["url"] == "https://server.vulnapp.id/mutillidae/index.php?page=login.php&redirect=https://example.com"
    assert r0["category"] in ("REDIRECT_SSRF_SURFACE", "AUTH_IDENTITY_SURFACE", "WEB_ENDPOINT")
    assert len(r0["skills"]) > 0

    r1 = step_res["results"][1]
    assert r1["url"] == "https://server.vulnapp.id/api/v1/user/123"
    assert r1["category"] in ("API_IDOR_SURFACE", "WEB_ENDPOINT")


def test_execute_plan_classify_fallback_when_zero_endpoints(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: server.vulnapp.id\nscope:\n  - server.vulnapp.id\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "ANALYSIS"}), encoding="utf-8")
    (eng_dir / "endpoints.json").write_text("[]", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    plan = {
        "target": "server.vulnapp.id",
        "steps": [
            {
                "step": 1,
                "name": "Attack Surface Mapping & Skill Matching",
                "action": "technology_mapping",
                "tool": "nyx-classify",
                "permitted": True,
            },
        ],
    }

    res = planner.execute_plan(plan)
    assert res["status"] == "success"
    step_res = res["step_results"][0]["result"]
    assert step_res["status"] == "success"
    assert "category" in step_res
    assert "skills" in step_res
    assert step_res["url"] == "server.vulnapp.id"


def test_decision_traceability_in_planner(tmp_path: Path, monkeypatch):
    from nyx.ai.planner import MissionPlanner

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: server.vulnapp.id\nscope:\n  - server.vulnapp.id\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "DISCOVERY"}), encoding="utf-8")
    (eng_dir / "endpoints.json").write_text("[]", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("server.vulnapp.id")

    assert plan.get("status") != "error"
    steps = plan.get("steps", [])
    assert len(steps) > 0

    # Verify every step has deterministic traceability tags
    for step in steps:
        assert "reason" in step
        assert "evidence" in step
        assert "knowledge_refs" in step
        assert "policy_status" in step
        assert isinstance(step["evidence"], list)
        assert isinstance(step["knowledge_refs"], list)


def test_autonomous_loop_zero_context_triggers_recon_first(tmp_path: Path, monkeypatch):
    """Test that autonomous loop on a zero-context target triggers recon first, then evaluates candidates."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: app.example.com\nscope:\n  - app.example.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "state.json").write_text(json.dumps({"state": "DISCOVERY"}), encoding="utf-8")
    (eng_dir / "endpoints.json").write_text("[]", encoding="utf-8")
    (eng_dir / "technologies.json").write_text("{}", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    planner.ai_manager.analyze = lambda ctx, prompt=None, provider_name=None: {
        "selected_index": 0,
        "decision": "proceed",
        "reasoning": "Step selection",
    }

    recon_called = False

    def fake_run_recon(target: str, **kwargs):
        nonlocal recon_called
        recon_called = True
        # Simulate populating endpoints and technologies into engagement memory
        (eng_dir / "endpoints.json").write_text(json.dumps([
            "https://app.example.com/api/v1/users",
            "https://app.example.com/auth/login",
            "https://app.example.com/graphql",
        ]), encoding="utf-8")
        (eng_dir / "technologies.json").write_text(json.dumps({
            "web_servers": ["Express"],
            "languages": ["Node.js"],
        }), encoding="utf-8")
        return {"status": "success", "sync_total": 3, "live_count": 3}

    with patch("nyx.application.recon_service.ReconService.run_recon", side_effect=fake_run_recon), \
         patch("nyx.core.findings.enrich_hypothesis_description", return_value={"ai_enriched": True, "description": "Enriched"}):
        res = planner.run_autonomous_loop(
            target="app.example.com",
            active_permitted=False,
            max_iterations=10,
        )

    assert recon_called is True
    assert res.get("recon_bootstrapped") is True
    assert res.get("status") in ("complete", "paused_for_approval")
    # Should have executed iterations corresponding to the discovered endpoints & tech
    assert len(res.get("iterations", [])) > 0
    # Confirm tested steps include context-driven candidates (e.g. GraphQL, Auth, API)
    step_reasons = [it["step"]["reason"] for it in res["iterations"]]
    assert any("GRAPHQL" in r or "AUTH" in r or "API" in r or "TECHNOLOGY" in r for r in step_reasons)


def test_autonomous_loop_zero_context_out_of_scope_blocks_recon(tmp_path: Path, monkeypatch):
    """Test that recon bootstrap respects policy scope checks and blocks out-of-scope targets."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: inscope.example.com\nscope:\n  - inscope.example.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)

    recon_called = False

    def fake_run_recon(target: str, **kwargs):
        nonlocal recon_called
        recon_called = True
        return {"status": "success"}

    with patch("nyx.application.recon_service.ReconService.run_recon", side_effect=fake_run_recon):
        res = planner.run_autonomous_loop(
            target="out-of-scope.example.com",
            active_permitted=False,
            max_iterations=5,
        )

    assert recon_called is False
    assert res.get("status") == "error"
    assert "out of scope" in res.get("error", "").lower()


def test_classification_generates_hypothesis_and_surfaces_validation(tmp_path: Path, monkeypatch):
    """Verify that nyx-classify creates a hypothesis finding entry in findings.json, which feeds Rule 4 validation candidate generation."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: bridge.target.com\nscope:\n  - bridge.target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps([
        "https://bridge.target.com/api/v1/users/profile",
        "https://bridge.target.com/api/v1/orders/12345",
    ]), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps({"web": ["Express"]}), encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)

    # 1. Execute a classification step
    classify_step = {
        "step": 1,
        "name": "REST API & Parameter Surface Analysis",
        "action": "technology_mapping",
        "tool": "nyx-classify",
        "target": "bridge.target.com",
        "reason": "API_SURFACE_DETECTED",
        "impact_class": "NON_DESTRUCTIVE",
    }
    with patch("nyx.core.findings.enrich_hypothesis_description", return_value={"ai_enriched": True, "description": "Enriched description"}):
        step_res = planner.execute_step(classify_step, "bridge.target.com", active_permitted=False)
    assert step_res.get("result", {}).get("status") == "success"

    # 2. Check findings.json was populated with hypothesis finding
    findings_file = eng_dir / "findings.json"
    assert findings_file.exists()
    findings_data = json.loads(findings_file.read_text(encoding="utf-8"))
    assert len(findings_data) >= 1
    hyp = findings_data[0]
    assert hyp.get("status") == "HYPOTHESIS"
    assert hyp.get("finding_id", "").startswith("FH-")

    # 3. Verify _select_steps now surfaces a validation candidate matching the hypothesis
    fresh_ctx = planner.context_engine.get_target_context("bridge.target.com")
    candidates = planner._select_steps(fresh_ctx)
    validate_candidates = [
        c for c in candidates
        if c.get("impact_class") == "DESTRUCTIVE" or c.get("tool") in ("nuclei", "sqlmap", "ffuf", "nyx-validate")
    ]
    assert len(validate_candidates) >= 1
    v_step = validate_candidates[0]
    assert v_step.get("impact_class") == "DESTRUCTIVE"
    assert any(hyp.get("finding_id") in ev for ev in v_step.get("evidence", []))


def test_autonomous_loop_bridges_classification_to_validation_and_pauses(tmp_path: Path, monkeypatch):
    """Verify end-to-end autonomous loop: classification runs -> hypothesis created -> validation candidate surfaces -> loop pauses for approval."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: auto-bridge.target.com\nscope:\n  - auto-bridge.target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps([
        "https://auto-bridge.target.com/api/v1/accounts/12345",
    ]), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps({"web": ["Express"]}), encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)

    # Mock analyze to select candidate 0 on iteration 1 (classification),
    # then select the destructive validation step when it surfaces
    def mock_analyze(ctx, prompt=None, provider_name=None):
        candidates = ctx.get("candidates", [])
        destructive_idx = next((i for i, c in enumerate(candidates) if c.get("impact_class") == "DESTRUCTIVE"), 0)
        return {
            "selected_index": destructive_idx,
            "decision": "proceed",
            "reasoning": "Step selection",
        }

    planner.ai_manager.analyze = mock_analyze

    with patch("nyx.core.findings.enrich_hypothesis_description", return_value={"ai_enriched": True, "description": "Enriched description"}):
        res = planner.run_autonomous_loop(
            target="auto-bridge.target.com",
            active_permitted=False,
            max_iterations=10,
        )

    # Loop should execute classification first, then pause when selecting the destructive validation step
    assert res.get("status") == "paused_for_approval"
    assert res.get("pending_step") is not None
    assert res.get("pending_step", {}).get("impact_class") == "DESTRUCTIVE"
    assert res.get("pending_step", {}).get("tool") in ("nuclei", "sqlmap", "ffuf", "nyx-validate")
    assert len(res.get("iterations", [])) >= 1









