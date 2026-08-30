"""
Comprehensive tests for Bug 1 (Provider threading / No Gemini quota fallback),
Bug 2 (Nuclei -jsonl flag compatibility), and Bug 3 (Strict IDOR hypothesis generation).
"""
import os
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from nyx.ai.manager import AIManager, detect_default_provider
from nyx.ai.planner import MissionPlanner
from nyx.agent.reasoning import ReasoningEngine
from nyx.execution.adapters.nuclei import NucleiAdapter, get_nuclei_template_for_vuln
from nyx.application.analysis_service import AnalysisService


def test_detect_default_provider_prefers_groq_over_gemini(monkeypatch):
    """Test that detect_default_provider picks groq when GROQ_API_KEY is configured."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test_key_123")
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy_test_gemini")
    monkeypatch.delenv("NYX_AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_PROVIDER", raising=False)

    prov = detect_default_provider()
    assert prov == "groq"


def test_planner_zero_gemini_calls_when_groq_selected(tmp_path: Path, monkeypatch):
    """Test that run_autonomous_loop uses Groq and NEVER touches Gemini."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_test_key_123")
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy_test_gemini")

    planner = MissionPlanner(base_dir=tmp_path)

    gemini_mock = MagicMock()
    groq_mock = MagicMock(return_value={"selected_index": 0, "decision": "proceed", "reasoning": "Groq decided"})

    with patch("nyx.ai.providers.gemini.GeminiProvider.analyze", gemini_mock), \
         patch("nyx.ai.providers.groq.GroqProvider.analyze", groq_mock):
        
        # Setup engagement
        eng_dir = tmp_path / ".engagement"
        eng_dir.mkdir(parents=True, exist_ok=True)
        (eng_dir / "target.yaml").write_text("target: test.local\nscope:\n  - test.local\n", encoding="utf-8")
        (eng_dir / "authorization.yaml").write_text("authorized: true\nmode: testing\nscope:\n  - test.local\n", encoding="utf-8")
        (eng_dir / "endpoints.json").write_text(json.dumps(["http://test.local/login"]), encoding="utf-8")

        res = planner.run_autonomous_loop(target="test.local", provider_name="groq", max_iterations=1)
        assert res.get("status") in ("max_iterations_reached", "complete", "paused_for_approval")

        # Confirm Gemini was NEVER called
        assert gemini_mock.call_count == 0
        # Confirm Groq was called
        assert groq_mock.call_count >= 1


def test_nuclei_adapter_uses_jsonl_flag():
    """Test that NucleiAdapter generates -jsonl and replaces legacy -json."""
    adapter = NucleiAdapter()
    
    # Default build_command
    cmd_default = adapter.build_command("http://example.com")
    assert "-jsonl" in cmd_default
    assert "-json" not in cmd_default

    # Legacy -json in arguments is converted to -jsonl
    cmd_legacy = adapter.build_command("http://example.com", arguments=["-t", "cves/", "-json"])
    assert "-jsonl" in cmd_legacy
    assert "-json" not in cmd_legacy


def test_nuclei_adapter_parses_jsonl_output():
    """Test that NucleiAdapter parses real JSONL output lines properly."""
    adapter = NucleiAdapter()
    sample_stdout = (
        '{"template-id":"cors-misconfig","info":{"name":"CORS Arbitrary Origin","severity":"medium"},"matched-at":"http://example.com/api"}\n'
        '{"template-id":"tech-detect","info":{"name":"Express Framework","severity":"info"},"matched-at":"http://example.com"}\n'
    )
    result = adapter.parse_result(stdout=sample_stdout, stderr="")
    assert result["count"] == 2
    assert result["vulnerabilities"][0]["template_id"] == "cors-misconfig"
    assert result["vulnerabilities"][0]["severity"] == "medium"
    assert result["vulnerabilities"][1]["name"] == "Express Framework"


def test_strict_idor_hypothesis_filtering(tmp_path: Path):
    """Test that root paths and static files produce ZERO IDOR hypotheses, while real object endpoints do."""
    from nyx.core import engagement
    engagement.init_engagement("target.com", base_dir=tmp_path)
    planner = MissionPlanner(base_dir=tmp_path)

    # 1. Non-IDOR endpoints (root, bare target, static files)
    non_idor_classifications = [
        {"url": "http://target.com/", "category": "WEB_ENDPOINT", "matches": {}, "skills": ["bb-methodology"]},
        {"url": "http://target.com/security.txt", "category": "WEB_ENDPOINT", "matches": {}, "skills": ["bb-methodology"]},
        {"url": "http://target.com/robots.txt", "category": "WEB_ENDPOINT", "matches": {}, "skills": ["bb-methodology"]},
        {"url": "http://target.com/server-status", "category": "WEB_ENDPOINT", "matches": {}, "skills": ["bb-methodology"]},
        {"url": "http://target.com/assets/app.js", "category": "WEB_ENDPOINT", "matches": {}, "skills": ["bb-methodology"]},
    ]
    created = planner._map_classification_to_hypotheses(non_idor_classifications, target="target.com")
    assert len(created) == 0, f"Expected 0 hypotheses for static/root paths, got {len(created)}"

    # 2. Real IDOR candidate endpoints
    real_idor_classifications = [
        {"url": "http://target.com/rest/user/1", "category": "API_IDOR_SURFACE", "matches": {"hunt-idor": "id=1"}, "skills": ["hunt-idor"]},
        {"url": "http://target.com/api/orders?order_id=452", "category": "API_IDOR_SURFACE", "matches": {"hunt-idor": "order_id=452"}, "skills": ["hunt-idor"]},
    ]
    created_real = planner._map_classification_to_hypotheses(real_idor_classifications, target="target.com")
    assert len(created_real) == 2
    assert all((f.get("finding", {}) or {}).get("vulnerability") == "IDOR" for f in created_real)
    assert (created_real[0].get("finding", {}) or {}).get("endpoint") == "http://target.com/rest/user/1"
    assert (created_real[1].get("finding", {}) or {}).get("endpoint") == "http://target.com/api/orders?order_id=452"


def test_analysis_service_does_not_inject_junk_idor():
    """Test that AnalysisService.classify_url does not append hunt-idor to empty matches."""
    svc = AnalysisService()
    res = svc.classify_url("http://target.com/security.txt")
    assert "hunt-idor" not in res.get("skills", [])
    assert res.get("skills") == ["bb-methodology"]


def test_groq_error_classifier_surfaces_status_code_and_full_message():
    """Test that _classify_groq_error captures HTTP status code and full error string."""
    from nyx.ai.providers.groq import _classify_groq_error

    class MockHttpError(Exception):
        def __init__(self, msg, status_code):
            super().__init__(msg)
            self.status_code = status_code

    ex = MockHttpError("Model groq/deepseek is rate limited", 429)
    classified = _classify_groq_error(ex)
    assert classified["status_code"] == 429
    assert "[HTTP 429]" in classified["message"]
    assert "Model groq/deepseek is rate limited" in classified["message"]


def test_groq_generate_detects_empty_content_distinctly():
    """Test that GroqProvider.generate detects empty content and raises descriptive error."""
    from nyx.ai.providers.groq import GroqProvider

    provider = GroqProvider()
    
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = ""
    mock_choice.message.reasoning = None
    mock_choice.finish_reason = "length"
    mock_client.chat.completions.create.return_value = MagicMock(choices=[mock_choice])

    provider._get_client = lambda: (mock_client, None)

    with pytest.raises(RuntimeError) as exc_info:
        provider.generate("Test prompt")
    
    assert "empty content" in str(exc_info.value).lower()
    assert "tokens exhausted by reasoning" in str(exc_info.value).lower()


def test_recon_log_distinguishes_new_vs_known_endpoints(tmp_path: Path, caplog):
    """Test that recon completion log clearly distinguishes new vs already-known endpoints."""
    from nyx.core import engagement, recon
    import logging

    engagement.init_engagement("recon-test.local", base_dir=tmp_path)
    
    with caplog.at_level(logging.INFO):
        tot, new_c, known_c = recon.sync_recon_to_engagement(
            target="recon-test.local",
            subs={"recon-test.local"},
            resolved={"recon-test.local": ["127.0.0.1"]},
            live=[{"url": "http://recon-test.local", "host": "recon-test.local"}],
            base_dir=tmp_path,
        )
        assert new_c == 2
        assert known_c == 0

        # Second sync on same endpoints
        tot2, new_c2, known_c2 = recon.sync_recon_to_engagement(
            target="recon-test.local",
            subs={"recon-test.local"},
            resolved={"recon-test.local": ["127.0.0.1"]},
            live=[{"url": "http://recon-test.local", "host": "recon-test.local"}],
            base_dir=tmp_path,
        )
        assert new_c2 == 0
        assert known_c2 == 2


def test_recon_path_included_target_probes_and_crawls_subpath(tmp_path: Path):
    """Test that recon with a path-included target probes and crawls the specific application path."""
    from nyx.core import recon
    from nyx.recon import content_discovery

    # 1. Test recon_http_probe retains and probes path
    with patch("nyx.core.recon.http_get") as mock_get:
        mock_get.return_value = (200, {"Server": "Apache/2.4"}, "<title>Mutillidae Home</title>")
        res = recon.recon_http_probe("https://server.vulnapp.id/mutillidae/")
        assert res is not None
        assert res["url"] == "https://server.vulnapp.id/mutillidae/"
        assert res["title"] == "Mutillidae Home"
        assert res["host"] == "server.vulnapp.id"

    # 2. Test content_discovery extracts HTML links under application path
    html_content = """
    <html>
        <body>
            <a href="index.php?page=login.php">Login</a>
            <a href="index.php?page=user-info.php">User Info</a>
            <form action="index.php?page=view-some-notes.php" method="POST"></form>
        </body>
    </html>
    """
    with patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.read.return_value = html_content.encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_open.return_value = mock_resp

        discovered = content_discovery.extract_spa_routes("https://server.vulnapp.id/mutillidae/")
        urls = [d["url"] for d in discovered]
        assert "https://server.vulnapp.id/mutillidae/index.php?page=login.php" in urls
        assert "https://server.vulnapp.id/mutillidae/index.php?page=user-info.php" in urls
        assert "https://server.vulnapp.id/mutillidae/index.php?page=view-some-notes.php" in urls


def test_cmd_recon_summary_populates_real_metrics(capsys):
    """Test that cmd_recon populates the summary block with real values, not None."""
    import argparse
    from nyx_cli.cli import cmd_recon
    from nyx.application.recon_service import ReconService

    mock_recon_data = {
        "status": "success",
        "target": "https://server.vulnapp.id/mutillidae/",
        "subdomains_count": 1,
        "resolved_count": 1,
        "live_count": 3,
        "content_discovery_count": 52,
        "out_dir": "recon/mutillidae",
        "sync_total": 56,
        "sync_new": 54,
        "sync_known": 2,
    }

    with patch.object(ReconService, "run_recon", return_value={"success": True, "data": mock_recon_data}):
        args = argparse.Namespace(target="https://server.vulnapp.id/mutillidae/", extra_arg=None, out=None, proxy=None, burp=False)
        ret = cmd_recon(args)
        assert ret == 0
        captured = capsys.readouterr()
        assert "Target:            https://server.vulnapp.id/mutillidae/" in captured.out
        assert "Subdomains:        1" in captured.out
        assert "Resolved:          1" in captured.out
        assert "HTTP-live:         3" in captured.out
        assert "Content-paths:     52" in captured.out
        assert "Discovered: 56 endpoints" in captured.out
        assert "New: 54" in captured.out
        assert "None" not in captured.out


def test_cli_agent_approvals_approve_deny(tmp_path: Path, capsys):
    """Test nyx agent approvals, approve, and deny CLI commands."""
    import argparse
    from nyx_cli.cli import cmd_agent
    from nyx.core import engagement as core_eng
    from nyx.agent.approval import ApprovalSystem

    core_eng.init_engagement("https://test.local/", base_dir=tmp_path)
    app_sys = ApprovalSystem(base_dir=tmp_path)

    # 1. Test empty approvals
    args_list = argparse.Namespace(agent_subcommand="approvals")
    with patch("nyx.agent.approval.ApprovalSystem._get_approvals_file", return_value=tmp_path / ".engagement" / "approvals.json"):
        ret = cmd_agent(args_list)
        assert ret == 0
        captured = capsys.readouterr()
        assert "No pending approvals." in captured.out

        # 2. Add pending approval and test approvals list
        app_sys.submit_for_approval({
            "action_id": "ACT-TEST01",
            "target": "https://test.local/admin",
            "action": "sql_injection_validation",
            "tool_name": "sqlmap",
            "impact_class": "DESTRUCTIVE",
            "impact_justification": "Active database dump probe",
        })

        ret = cmd_agent(args_list)
        assert ret == 0
        captured = capsys.readouterr()
        assert "ACT-TEST01" in captured.out
        assert "DESTRUCTIVE" in captured.out
        assert "Active database dump probe" in captured.out

        # 3. Test approve
        with patch("nyx.ai.planner.MissionPlanner.execute_step", return_value={"tool": "sqlmap", "result": {"status": "success"}}):
            args_app = argparse.Namespace(agent_subcommand="approve", action_id="ACT-TEST01")
            ret_app = cmd_agent(args_app)
            assert ret_app == 0
            captured = capsys.readouterr()
            assert "Action 'ACT-TEST01' approved and executed successfully." in captured.out

        # 4. Add another action and test deny
        app_sys.submit_for_approval({
            "action_id": "ACT-TEST02",
            "target": "https://test.local/delete",
            "action": "file_delete",
            "tool_name": "nuclei",
            "impact_class": "DESTRUCTIVE",
            "impact_justification": "Dangerous file delete probe",
        })

        args_deny = argparse.Namespace(agent_subcommand="deny", action_id="ACT-TEST02", reason="Dangerous action denied")
        ret_deny = cmd_agent(args_deny)
        assert ret_deny == 0
        captured = capsys.readouterr()
        assert "Action 'ACT-TEST02' denied successfully." in captured.out



