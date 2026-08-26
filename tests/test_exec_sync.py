import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from nyx.core.recon import sync_exec_to_engagement
from nyx.application.execution_service import ExecutionService
from nyx.models.execution import ExecutionResult, ExecutionStatus

def test_sync_exec_katana_style():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        eng_dir = base_dir / ".engagement"
        eng_dir.mkdir(parents=True, exist_ok=True)
        
        exec_res = {
            "tool_name": "katana",
            "target": "http://testaspnet.vulnweb.com",
            "metadata": {
                "endpoints": [
                    "http://testaspnet.vulnweb.com/login.aspx",
                    "http://testaspnet.vulnweb.com/search.aspx",
                ],
                "assets_found": 2,
                "parsed": True,
            }
        }
        
        new_cnt, known_cnt = sync_exec_to_engagement(exec_res, base_dir=base_dir)
        assert new_cnt == 2
        assert known_cnt == 0
        
        ep_file = eng_dir / "endpoints.json"
        assert ep_file.exists()
        endpoints = json.loads(ep_file.read_text(encoding="utf-8"))
        assert len(endpoints) == 2
        for ep in endpoints:
            assert ep["source"] == "exec"
            assert "exec" in ep["sources"]
            assert ep["host"] == "testaspnet.vulnweb.com"

def test_sync_exec_httpx_style():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        eng_dir = base_dir / ".engagement"
        eng_dir.mkdir(parents=True, exist_ok=True)
        
        exec_res = {
            "tool_name": "httpx",
            "target": "http://testaspnet.vulnweb.com",
            "metadata": {
                "live_hosts": [
                    {
                        "url": "http://testaspnet.vulnweb.com",
                        "status": 200,
                        "title": "ACME Corp Test Site",
                        "server": "Microsoft-IIS/8.5",
                        "technologies": ["ASP.NET", "IIS"],
                    }
                ],
                "parsed": True,
            }
        }
        
        new_cnt, known_cnt = sync_exec_to_engagement(exec_res, base_dir=base_dir)
        assert new_cnt == 1
        assert known_cnt == 0
        
        ep_file = eng_dir / "endpoints.json"
        endpoints = json.loads(ep_file.read_text(encoding="utf-8"))
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep["url"] == "http://testaspnet.vulnweb.com"
        assert ep["status"] == 200
        assert ep["title"] == "ACME Corp Test Site"
        assert ep["server"] == "Microsoft-IIS/8.5"
        assert ep["source"] == "exec"
        assert ep["sources"] == ["exec"]

def test_sync_exec_merge_existing_recon():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        eng_dir = base_dir / ".engagement"
        eng_dir.mkdir(parents=True, exist_ok=True)
        
        ep_file = eng_dir / "endpoints.json"
        initial = [
            {
                "url": "http://testaspnet.vulnweb.com",
                "host": "testaspnet.vulnweb.com",
                "status": None,
                "server": "",
                "title": "",
                "source": "recon",
                "sources": ["recon"],
            }
        ]
        ep_file.write_text(json.dumps(initial), encoding="utf-8")
        
        exec_res = {
            "tool_name": "httpx",
            "target": "http://testaspnet.vulnweb.com",
            "metadata": {
                "live_hosts": [
                    {
                        "url": "http://testaspnet.vulnweb.com",
                        "status": 200,
                        "title": "ACME Corp",
                        "server": "Microsoft-IIS/8.5",
                    }
                ]
            }
        }
        
        new_cnt, known_cnt = sync_exec_to_engagement(exec_res, base_dir=base_dir)
        assert new_cnt == 0
        assert known_cnt == 1
        
        endpoints = json.loads(ep_file.read_text(encoding="utf-8"))
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep["source"] == "recon"
        assert "recon" in ep["sources"]
        assert "exec" in ep["sources"]
        assert ep["status"] == 200
        assert ep["title"] == "ACME Corp"
        assert ep["server"] == "Microsoft-IIS/8.5"

def test_execution_service_invokes_sync():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        svc = ExecutionService(base_dir=base_dir)
        
        mock_result = ExecutionResult(
            execution_id="exec-123",
            tool_name="httpx",
            target="http://testaspnet.vulnweb.com",
            status=ExecutionStatus.COMPLETED.value,
            exit_code=0,
            stdout="{}",
            stderr="",
            metadata={"live_hosts": [{"url": "http://testaspnet.vulnweb.com", "status": 200}]},
        )
        
        with patch.object(svc.engine, "execute", return_value=mock_result), \
             patch("nyx.core.recon.sync_exec_to_engagement") as mock_sync:
            res = svc.run_tool("httpx", "http://testaspnet.vulnweb.com")
            assert res.is_success
            mock_sync.assert_called_once()

def test_httpx_adapter_pretty_json():
    from nyx.execution.adapters.httpx import HttpxAdapter
    adapter = HttpxAdapter()
    pretty_json = """
    {
        "timestamp": "2026-08-23T03:32:33.481118816+05:30",
        "port": "443",
        "url": "https://server.vulnapp.id/mutillidae/",
        "input": "https://server.vulnapp.id/mutillidae/",
        "scheme": "https",
        "webserver": "nginx/1.24.0 (Ubuntu)",
        "status_code": 200,
        "title": "NOWASP Mutillidae II",
        "tech": [
            "nginx:1.24.0",
            "php:5.2.4",
            "ubuntu"
        ]
    }
    """
    res = adapter.parse_result(pretty_json, "")
    assert res["parsed"] is True
    assert len(res["live_hosts"]) == 1
    host = res["live_hosts"][0]
    assert host["url"] == "https://server.vulnapp.id/mutillidae/"
    assert host["status"] == 200
    assert host["title"] == "NOWASP Mutillidae II"
    assert host["server"] == "nginx/1.24.0 (Ubuntu)"
    assert "ubuntu" in res["technologies"]

def test_httpx_adapter_jsonl_with_noise():
    from nyx.execution.adapters.httpx import HttpxAdapter
    adapter = HttpxAdapter()
    noisy_output = """
    __httpx__
    [INF] Starting probing
    {"url": "https://example.com", "status_code": 200, "title": "Example", "webserver": "Apache"}
    [WRN] Failed to resolve bad.test
    {"url": "https://test.com", "status_code": 301, "title": "Redirect", "webserver": "Cloudflare"}
    [INF] Finished in 1.2s
    """
    res = adapter.parse_result(noisy_output, "")
    assert res["parsed"] is True
    assert len(res["live_hosts"]) == 2
    assert res["live_hosts"][0]["url"] == "https://example.com"
    assert res["live_hosts"][1]["url"] == "https://test.com"


def test_httpx_adapter_empty_stdout_warning():
    from nyx.execution.adapters.httpx import HttpxAdapter
    adapter = HttpxAdapter()

    # 1. Completely empty stdout (e.g. internal timeout/unreachable)
    res_empty = adapter.parse_result("", "[INF] Banner only")
    assert res_empty["parsed"] is False
    assert res_empty["live_hosts"] == []
    assert res_empty["count"] == 0
    assert "warning" in res_empty
    assert "No output received from httpx" in res_empty["warning"]

    # 2. Whitespace-only stdout
    res_ws = adapter.parse_result("   \n  \t ", "")
    assert res_ws["parsed"] is False
    assert "warning" in res_ws

    # 3. Valid stdout with hosts -> parsed is True, no warning
    valid_json = '{"url": "https://example.com", "status_code": 200}'
    res_valid = adapter.parse_result(valid_json, "")
    assert res_valid["parsed"] is True
    assert len(res_valid["live_hosts"]) == 1
    assert "warning" not in res_valid


def test_sync_exec_writes_technologies_and_deduplicates():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        eng_dir = base_dir / ".engagement"
        eng_dir.mkdir(parents=True, exist_ok=True)

        exec_res = {
            "tool_name": "httpx",
            "target": "https://server.vulnapp.id/mutillidae/",
            "metadata": {
                "live_hosts": [
                    {
                        "url": "https://server.vulnapp.id/mutillidae/",
                        "status": 200,
                        "title": "NOWASP Mutillidae II",
                        "server": "nginx/1.24.0 (Ubuntu)",
                        "tech": ["Nginx:1.24.0", "PHP:5.2.4", "Ubuntu", "jQuery"],
                    }
                ],
                "technologies": ["Nginx:1.24.0", "PHP:5.2.4", "Ubuntu", "jQuery"],
                "parsed": True,
            }
        }

        # 1. First sync call creates/updates technologies.json
        new_cnt, known_cnt = sync_exec_to_engagement(exec_res, base_dir=base_dir)
        assert new_cnt == 1
        assert known_cnt == 0

        tech_file = eng_dir / "technologies.json"
        assert tech_file.exists()
        t_data = json.loads(tech_file.read_text(encoding="utf-8"))
        assert "frameworks" in t_data
        assert "PHP:5.2.4" in t_data["frameworks"]
        assert "Nginx:1.24.0" in t_data["frameworks"]
        assert "jQuery" in t_data["frameworks"]
        assert "Ubuntu" in t_data["frameworks"]
        initial_frameworks = list(t_data["frameworks"])

        # 2. Second sync call with same result should deduplicate
        new_cnt2, known_cnt2 = sync_exec_to_engagement(exec_res, base_dir=base_dir)
        assert new_cnt2 == 0
        assert known_cnt2 == 1

        t_data2 = json.loads(tech_file.read_text(encoding="utf-8"))
        assert t_data2["frameworks"] == initial_frameworks


def test_context_engine_flattens_categorized_technologies():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        eng_dir = base_dir / ".engagement"
        eng_dir.mkdir(parents=True, exist_ok=True)

        categorized_tech = {
            "frameworks": ["PHP:5.2.4", "jQuery", "Laravel"],
            "servers": ["nginx/1.24.0", "Apache"],
            "APIs": ["REST", "GraphQL"],
            "authentication": ["JWT"],
            "cloud": ["AWS"],
            "databases": ["MySQL", "PostgreSQL"],
        }
        (eng_dir / "technologies.json").write_text(json.dumps(categorized_tech), encoding="utf-8")

        from nyx.ai.context import ContextEngine
        ctx_engine = ContextEngine(base_dir=base_dir)
        ctx = ctx_engine.get_target_context("server.vulnapp.id")

        techs = ctx["technologies"]
        assert isinstance(techs, list)
        assert "PHP:5.2.4" in techs
        assert "jQuery" in techs
        assert "nginx/1.24.0" in techs
        assert "GraphQL" in techs
        assert "MySQL" in techs
        assert len(techs) == 11


def test_sync_exec_filters_out_of_scope_urls():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)
        eng_dir = base_dir / ".engagement"
        eng_dir.mkdir(parents=True, exist_ok=True)

        (eng_dir / "target.yaml").write_text("target: server.vulnapp.id\nscope:\n  - server.vulnapp.id\n", encoding="utf-8")
        (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

        exec_res = {
            "tool_name": "katana",
            "target": "https://server.vulnapp.id/mutillidae/",
            "metadata": {
                "endpoints": [
                    "https://server.vulnapp.id/mutillidae/index.php",
                    "https://server.vulnapp.id/mutillidae/login.php",
                    "https://en.wikipedia.org/wiki/Cross-site_scripting",
                    "https://irongeek.com/xss.php",
                    "https://samurai.inguardians.com/",
                ],
                "parsed": True,
            }
        }

        new_cnt, known_cnt = sync_exec_to_engagement(exec_res, base_dir=base_dir)
        assert new_cnt == 2
        assert known_cnt == 0

        ep_file = eng_dir / "endpoints.json"
        endpoints = json.loads(ep_file.read_text(encoding="utf-8"))
        assert len(endpoints) == 2
        urls = [e["url"] for e in endpoints]
        assert "https://server.vulnapp.id/mutillidae/index.php" in urls
        assert "https://server.vulnapp.id/mutillidae/login.php" in urls
        assert not any("wikipedia.org" in u for u in urls)
        assert not any("irongeek.com" in u for u in urls)
        assert not any("inguardians.com" in u for u in urls)


def test_cmd_exec_status_missing_eid(capsys):
    import argparse
    from nyx_cli.cli import cmd_exec

    args = argparse.Namespace(
        tool="status",
        target="",
        exec_subcommand="status",
        dry_run=False,
    )
    ret = cmd_exec(args)
    assert ret == 1
    captured = capsys.readouterr().out
    assert "Execution ID is required" in captured
    assert "nyx exec status EXEC-XXXXXXXX" in captured
    assert "nyx exec history" in captured


def test_cmd_exec_status_with_eid(tmp_path: Path, monkeypatch, capsys):
    import argparse
    from nyx_cli.cli import cmd_exec

    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = eng_dir / "executions" / "EXEC-TEST-001"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    (artifacts_dir / "result.json").write_text(json.dumps({
        "execution_id": "EXEC-TEST-001",
        "tool_name": "httpx",
        "target": "example.com",
        "execution_class": "SAFE_PASSIVE",
        "exit_code": 0,
        "authorized": True,
        "scope_status": "IN_SCOPE",
        "dry_run": False,
    }), encoding="utf-8")

    args = argparse.Namespace(
        tool="status",
        target="EXEC-TEST-001",
        exec_subcommand="status",
        dry_run=False,
    )
    ret = cmd_exec(args)
    assert ret == 0
    captured = capsys.readouterr().out
    assert "NYX Tool Execution Status: EXEC-TEST-001" in captured
    assert "Tool:       httpx" in captured
    assert "Exit Code:  0" in captured




