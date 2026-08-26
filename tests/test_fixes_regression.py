"""
Regression test suite for NYX 5 Confirmed Architectural Fixes.
"""
from __future__ import annotations

import json
from pathlib import Path
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
