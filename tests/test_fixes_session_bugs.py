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
    with patch("nyx.recon.content_discovery.is_hostname_in_scope", return_value=True), patch("urllib.request.urlopen") as mock_open:
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
    ApprovalSystem._shared_pending_queue.clear()
    ApprovalSystem._shared_approved_actions.clear()
    ApprovalSystem._shared_denied_actions.clear()
    app_sys = ApprovalSystem(base_dir=tmp_path)

    # 1. Test empty approvals
    args_list = argparse.Namespace(agent_subcommand="approvals")
    with patch("nyx.core.engagement._get_eng_dir", return_value=tmp_path / ".engagement"), \
         patch("nyx.agent.approval.ApprovalSystem._get_approvals_file", return_value=tmp_path / ".engagement" / "approvals.json"):
        ApprovalSystem._shared_pending_queue.clear()
        ApprovalSystem._shared_approved_actions.clear()
        ApprovalSystem._shared_denied_actions.clear()
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


def test_tier1_skill_summaries_budget_and_content():
    """Test that Tier 1 candidate skill summary extraction stays under budget and pulls real playbook descriptions."""
    from nyx.core.skills import get_candidates_skill_summaries

    candidates = [
        {"name": "Step 1", "knowledge_refs": ["hunt-file-upload", "hunt-lfi"]},
        {"name": "Step 2", "knowledge_refs": ["hunt-sqli", "7-question-gate"]},
        {"name": "Step 3", "knowledge_refs": ["hunt-auth-bypass", "hunt-ato"]},
    ]

    summaries = get_candidates_skill_summaries(candidates, max_tokens=500)
    assert summaries != ""
    assert "hunt-file-upload" in summaries or "hunt-lfi" in summaries
    # 500 tokens roughly translates to <= 2000 chars
    assert len(summaries) <= 2000


def test_tier2_skill_content_prioritizes_verification_gates():
    """Test that Tier 2 full content extraction prioritizes verification gates when budget is capped."""
    from nyx.core.skills import get_skill_content

    # Request small budget (e.g. 300 tokens ~ 1200 chars) on a long skill file like hunt-lfi
    content = get_skill_content("hunt-lfi", max_tokens=300)
    assert content is not None
    assert len(content) <= 1300
    # Confirm high-priority verification / confirmation keywords are retained
    content_lower = content.lower()
    assert "confirmation" in content_lower or "gate" in content_lower or "crown jewel" in content_lower


def test_autonomous_loop_injects_tier1_prompt_and_tier2_selected_candidate(tmp_path: Path, monkeypatch):
    """Test that autonomous loop builds decision_prompt with Reference Playbooks and populates playbook_guidance on selected candidate."""
    from nyx.ai.planner import MissionPlanner
    from nyx.core import engagement as core_eng
    from nyx.application.recon_service import ReconService
    import json

    monkeypatch.chdir(tmp_path)
    core_eng.init_engagement("https://skill-test.local/", reset=True, force=True, base_dir=tmp_path)
    eng_dir = tmp_path / ".engagement"
    (eng_dir / "endpoints.json").write_text(json.dumps([
        {"url": "https://skill-test.local/index.php?page=upload.php", "host": "skill-test.local"}
    ]), encoding="utf-8")

    captured_prompt = None

    def mock_analyze(ctx, prompt=None, provider_name=None):
        nonlocal captured_prompt
        captured_prompt = prompt
        return {"selected_index": 0, "decision": "proceed", "reasoning": "Selected based on LFI playbook guidance"}

    planner = MissionPlanner(base_dir=tmp_path)
    planner.ai_manager.analyze = mock_analyze

    res = planner.run_autonomous_loop("https://skill-test.local/", active_permitted=False, max_iterations=1)

    # 1. Tier 1 prompt check: Reference Playbooks section present
    assert captured_prompt is not None
    assert "Reference Playbooks (Methodology & Gate Guidance):" in captured_prompt
    assert "hunt-file-upload" in captured_prompt or "hunt-lfi" in captured_prompt or "bb-methodology" in captured_prompt

    # 2. Tier 2 selected candidate check: only selected candidate receives playbook_guidance
    iterations = res.get("iterations", [])
    assert len(iterations) >= 1
    selected_step = iterations[0].get("step", {})
    assert "playbook_guidance" in selected_step
    assert selected_step["playbook_guidance"] is not None


def test_finding_report_generation_returns_real_markdown_and_draft_key(tmp_path: Path):
    """Test that finding report generation produces real Markdown with draft key and VRT/CVSS structure."""
    from nyx.application.finding_service import FindingService
    from nyx.core import engagement as core_eng
    import json

    core_eng.init_engagement("https://test.local/", reset=True, force=True, base_dir=tmp_path)
    eng_dir = tmp_path / ".engagement"
    findings_file = eng_dir / "findings.json"
    findings_file.write_text(json.dumps([
        {
            "finding_id": "FH-2026-001",
            "title": "Local File Inclusion via page Parameter",
            "severity": "High",
            "endpoint": "https://test.local/mutillidae/index.php?page=arbitrary-file-inclusion.php",
            "parameter": "page",
            "vulnerability": "Local File Inclusion",
            "evidence": "1. GET https://test.local/index.php?page=../../etc/passwd\n2. Response contains root:x:0:0:",
            "remediation": "Validate input against an allowlist.",
        }
    ]), encoding="utf-8")

    service = FindingService(base_dir=tmp_path)
    res = service.report(finding_id="FH-2026-001", platform="bugcrowd")

    assert res.get("status") == "success"
    assert "draft" in res
    draft_md = res["draft"]
    assert "# Vulnerability Report" in draft_md or "## Summary" in draft_md or "FH-2026-001" in draft_md
    assert "Local File Inclusion" in draft_md
    assert "https://test.local/mutillidae/index.php" in draft_md


def test_finding_report_generation_error_raises_http_400(tmp_path: Path):
    """Test that requesting report for a non-existent finding returns error status and triggers HTTP 400."""
    from nyx.application.finding_service import FindingService
    from nyx.web.routes.findings import generate_finding_report
    from fastapi import HTTPException
    import pytest
    import asyncio

    core_eng_dir = tmp_path / ".engagement"
    core_eng_dir.mkdir(parents=True, exist_ok=True)
    (core_eng_dir / "findings.json").write_text("[]", encoding="utf-8")

    service = FindingService(base_dir=tmp_path)

    # 1. Service level returns status: error
    res = service.report(finding_id="FH-NONEXISTENT", platform="bugcrowd")
    assert res.get("status") == "error"

    # 2. Web route raises HTTPException(status_code=400)
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(generate_finding_report(finding_id="FH-NONEXISTENT", platform="bugcrowd", service=service))
    assert exc_info.value.status_code == 400
    assert "not found" in exc_info.value.detail.get("message", "").lower()


def test_ai_authored_report_generation_produces_non_placeholder_content(tmp_path: Path, monkeypatch):
    """Test that AI-authored report generation produces rich non-placeholder content and sets ai_generated=True."""
    from nyx.application.finding_service import FindingService
    from nyx.core import engagement as core_eng
    from nyx.ai.manager import AIManager
    import json

    core_eng.init_engagement("https://test.local/", reset=True, force=True, base_dir=tmp_path)
    eng_dir = tmp_path / ".engagement"
    findings_file = eng_dir / "findings.json"
    findings_file.write_text(json.dumps([
        {
            "finding_id": "FH-2026-001",
            "title": "Local File Inclusion on index.php",
            "severity": "High",
            "status": "HYPOTHESIS",
            "endpoint": "https://test.local/index.php?page=arbitrary-file-inclusion.php",
            "parameter": "page",
            "vulnerability": "Local File Inclusion",
            "description": "Classification identified page parameter LFI vulnerability.",
        }
    ]), encoding="utf-8")

    mock_ai_json = json.dumps({
        "vrt_category": "Server-Side Injection > Local File Inclusion",
        "severity_justification": "High severity due to sensitive configuration file read vector.",
        "summary": "Detailed AI technical summary regarding index.php page parameter handling in PHP.",
        "steps_to_reproduce": "1. Send curl GET with ../../etc/passwd\n2. Inspect response body.",
        "impact": "Unconfirmed hypothesis: would allow unauthorized local file reads if validated.",
        "remediation": "Implement an allowlist for page parameter values."
    })

    monkeypatch.setattr(AIManager, "generate", lambda self, prompt, options=None: mock_ai_json)

    service = FindingService(base_dir=tmp_path)
    res = service.report(finding_id="FH-2026-001", platform="bugcrowd", use_ai=True)

    assert res.get("status") == "success"
    assert res.get("ai_generated") is True
    assert res.get("fallback") is False
    draft = res.get("draft", "")

    # Confirm non-placeholder content
    assert "Detailed AI technical summary" in draft
    assert "Server-Side Injection > Local File Inclusion" in draft
    assert "High severity due to sensitive configuration file read vector." in draft
    assert "Implement an allowlist for page parameter values." in draft
    assert "Unconfirmed hypothesis: would allow unauthorized local file reads" in draft
    assert "_<VRT-path>_" not in draft
    assert "(fill in steps)" not in draft


def test_ai_report_generation_fallback_path_is_distinguishable(tmp_path: Path, monkeypatch):
    """Test that when AI generation fails or is disabled, fallback path is clearly marked."""
    from nyx.application.finding_service import FindingService
    from nyx.core import engagement as core_eng
    from nyx.ai.manager import AIManager
    import json

    core_eng.init_engagement("https://test.local/", reset=True, force=True, base_dir=tmp_path)
    eng_dir = tmp_path / ".engagement"
    findings_file = eng_dir / "findings.json"
    findings_file.write_text(json.dumps([
        {
            "finding_id": "FH-2026-001",
            "title": "Local File Inclusion on index.php",
            "severity": "High",
            "status": "HYPOTHESIS",
            "endpoint": "https://test.local/index.php?page=arbitrary-file-inclusion.php",
        }
    ]), encoding="utf-8")

    # Force AI failure
    monkeypatch.setattr(AIManager, "generate", lambda self, prompt, options=None: (_ for _ in ()).throw(RuntimeError("API down")))

    service = FindingService(base_dir=tmp_path)
    res = service.report(finding_id="FH-2026-001", platform="bugcrowd", use_ai=True)

    assert res.get("status") == "success"
    assert res.get("ai_generated") is False
    assert res.get("fallback") is True
    draft = res.get("draft", "")
    assert "Fallback Report Template" in draft


def test_duplicate_check_prevents_race_and_checks_directory_subdirs(tmp_path: Path):
    """Test that duplicate_check inspects on-disk subdirectories and prevents duplicate creation even without findings.json."""
    from nyx.application.finding_service import FindingService
    from nyx.core import engagement as core_eng
    from nyx.core.findings import duplicate_check, create_finding

    core_eng.init_engagement("https://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)
    service = FindingService(base_dir=tmp_path)

    # 1. Create first finding
    res1 = service.create(
        title="File Upload Surface on arbitrary-file-inclusion.php",
        endpoint="https://server.vulnapp.id/mutillidae/index.php?page=arbitrary-file-inclusion.php",
        vulnerability="Arbitrary File Upload",
        severity="High",
    )
    assert res1.get("status") == "success"
    fid1 = res1.get("finding_id")

    # 2. Simulate stale/missing findings.json by deleting findings.json while subdirs exist
    findings_json_file = tmp_path / ".engagement" / "findings.json"
    if findings_json_file.exists():
        findings_json_file.unlink()

    # 3. duplicate_check directly
    dup_res = duplicate_check(
        endpoint="https://server.vulnapp.id/mutillidae/index.php?page=arbitrary-file-inclusion.php",
        vulnerability="Arbitrary File Upload",
        base_dir=tmp_path,
    )
    assert dup_res.get("is_duplicate") is True
    assert dup_res.get("existing_finding", {}).get("finding_id") == fid1

    # 4. Attempt creating duplicate finding
    res2 = service.create(
        title="File Upload Surface on arbitrary-file-inclusion.php",
        endpoint="https://server.vulnapp.id/mutillidae/index.php?page=arbitrary-file-inclusion.php",
        vulnerability="Arbitrary File Upload",
        severity="High",
    )
    assert res2.get("is_duplicate") is True
    assert res2.get("status") == "duplicate"
    assert res2.get("finding_id") == fid1


def test_differentiated_authentication_classification_hypotheses(tmp_path: Path):
    """Test that auth-family endpoints produce differentiated, semantics-specific vulnerability hypotheses."""
    from nyx.ai.planner import MissionPlanner
    from nyx.core import engagement as core_eng

    core_eng.init_engagement("http://localhost:8888/", reset=True, force=True, base_dir=tmp_path)
    planner = MissionPlanner(base_dir=tmp_path)

    classified_results = [
        {"url": "http://localhost:8888/api/auth/forget-password", "category": "auth", "skills": [], "matches": {}},
        {"url": "http://localhost:8888/api/auth/v3/check-otp", "category": "auth", "skills": [], "matches": {}},
        {"url": "http://localhost:8888/api/auth/v4.0/user/login-with-token", "category": "auth", "skills": [], "matches": {}},
        {"url": "http://localhost:8888/api/auth/unlock", "category": "auth", "skills": [], "matches": {}},
        {"url": "http://localhost:8888/api/auth/signup", "category": "auth", "skills": [], "matches": {}},
        {"url": "http://localhost:8888/api/auth/login", "category": "auth", "skills": [], "matches": {}},
    ]

    hypotheses = planner._map_classification_to_hypotheses(
        classified_results=classified_results,
        target="http://localhost:8888/",
    )

    vuln_by_url = {h["finding"]["endpoint"]: h["finding"]["vulnerability"] for h in hypotheses if "finding" in h}

    assert vuln_by_url.get("http://localhost:8888/api/auth/forget-password") == "Broken Password Recovery"
    assert vuln_by_url.get("http://localhost:8888/api/auth/v3/check-otp") == "MFA Bypass"
    assert vuln_by_url.get("http://localhost:8888/api/auth/v4.0/user/login-with-token") == "Token Handling Flaw"
    assert vuln_by_url.get("http://localhost:8888/api/auth/unlock") == "Account Lockout Bypass"
    assert vuln_by_url.get("http://localhost:8888/api/auth/signup") == "Insecure Registration"
    assert vuln_by_url.get("http://localhost:8888/api/auth/login") == "Authentication Bypass"


def test_autonomous_loop_flags_ai_degraded_on_error_or_429(tmp_path: Path, monkeypatch):
    """Test that when AI returns 429 or an error, the autonomous loop fails closed with status ai_unavailable."""
    from nyx.ai.planner import MissionPlanner
    from nyx.core import engagement as core_eng
    from nyx.ai.manager import AIManager

    core_eng.init_engagement("https://test.local/", reset=True, force=True, base_dir=tmp_path)
    core_eng.add_memory(type_="endpoint", value="https://test.local/api/users", endpoint="https://test.local/api/users", base_dir=tmp_path)

    # Mock analyze returning 429 error
    monkeypatch.setattr(
        AIManager,
        "analyze",
        lambda self, ctx, prompt=None, provider_name=None: {
            "status": "error",
            "error_type": "rate_limit",
            "message": "Groq API rate limit reached (HTTP 429)",
        }
    )

    planner = MissionPlanner(base_dir=tmp_path)
    res = planner.run_autonomous_loop("https://test.local/", max_iterations=2)

    assert res.get("status") == "ai_unavailable"
    assert res.get("ai_degraded") is True
    assert "429" in str(res.get("degradation_reason")) or "rate limit" in str(res.get("degradation_reason")).lower()
    assert res.get("iteration_halted") == 1
    # Fail-closed: No steps executed when AI fails on iteration 1
    assert len(res.get("iterations", [])) == 0
    assert "AI provider unavailable" in res.get("message", "")
    assert "Autonomous mission halted" in res.get("message", "")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_approve_agent_action_non_blocking_concurrent_requests(tmp_path: Path, monkeypatch):
    """Test that POST /api/v1/agent/approve/{id} does not block the FastAPI event loop during tool execution."""
    import asyncio
    import time
    from httpx import AsyncClient, ASGITransport
    from nyx.web.app import create_app
    from nyx.application.agent_service import AgentService
    from nyx.core import engagement as core_eng

    core_eng.init_engagement("http://localhost:3000/", reset=True, force=True, base_dir=tmp_path)
    app = create_app()

    from nyx.web.auth import get_or_create_api_token
    auth_tok = get_or_create_api_token()
    headers = {"Authorization": f"Bearer {auth_tok}"}

    # Warm up client to initialize routes
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.get("/api/v1/findings", headers=headers)

        # Mock approve_action on AgentService to simulate long-running subprocess (3.0s)
        def _slow_approve(self, action_id: str):
            time.sleep(3.0)
            return {"success": True, "action_id": action_id, "status": "approved_and_executed"}

        monkeypatch.setattr(AgentService, "approve_action", _slow_approve)

        # Start slow approve action in background task
        approve_task = asyncio.create_task(
            client.post("/api/v1/agent/approve/ACT-TEST01", headers=headers)
        )

        # Wait 0.1s to ensure approve_task is actively in-flight
        await asyncio.sleep(0.1)

        # Concurrently request GET /api/v1/health and measure latency
        start_t = time.time()
        health_resp = await client.get("/api/v1/health", headers=headers)
        elapsed = time.time() - start_t

        # Must return before the 3.0s approve task completes (< 2.5s)
        assert health_resp.status_code == 200
        assert elapsed < 2.5

        approve_resp = await approve_task
        assert approve_resp.status_code == 200


def test_rule4_generates_multi_tool_menu_based_on_hypothesis_and_stack(tmp_path: Path):
    """Test that Rule 4 generates candidates across sqlmap, ffuf, and nuclei based on hypothesis and tech stack."""
    from nyx.ai.planner import MissionPlanner
    from nyx.core import engagement as core_eng

    core_eng.init_engagement("https://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)
    planner = MissionPlanner(base_dir=tmp_path)

    # 1. Test SQLi hypothesis -> sqlmap candidate generated with DESTRUCTIVE class
    sqli_context = {
        "target": "https://server.vulnapp.id/mutillidae/",
        "technologies": ["PHP", "MySQL", "Apache"],
        "endpoints": ["https://server.vulnapp.id/mutillidae/index.php?page=user-info.php"],
        "findings": [
            {
                "finding_id": "FH-2026-001",
                "title": "SQL Injection on user-info.php",
                "vulnerability": "SQL Injection",
                "status": "HYPOTHESIS",
                "endpoint": "https://server.vulnapp.id/mutillidae/index.php?page=user-info.php",
            }
        ],
        "tested_vectors": [],
    }

    steps = planner._select_steps(context=sqli_context)
    tools = [s.get("tool") for s in steps]
    sqlmap_steps = [s for s in steps if s.get("tool") == "sqlmap"]

    assert "sqlmap" in tools
    assert len(sqlmap_steps) >= 1
    assert sqlmap_steps[0]["impact_class"] == "DESTRUCTIVE"
    assert sqlmap_steps[0]["reason"] == "SQL_INJECTION_VALIDATION"
    assert "--batch" in sqlmap_steps[0].get("arguments", [])

    # 2. Test LFI/traversal hypothesis on PHP stack -> ffuf candidate with stack-aware wordlist & parameterized target
    lfi_context = {
        "target": "https://server.vulnapp.id/mutillidae/",
        "technologies": ["PHP", "Apache"],
        "endpoints": ["https://server.vulnapp.id/mutillidae/index.php?page=arbitrary-file-inclusion.php"],
        "findings": [
            {
                "finding_id": "FH-2026-002",
                "title": "Arbitrary File Inclusion on index.php",
                "vulnerability": "Arbitrary File Upload & Traversal",
                "status": "HYPOTHESIS",
                "endpoint": "https://server.vulnapp.id/mutillidae/index.php?page=arbitrary-file-inclusion.php",
            }
        ],
        "tested_vectors": [],
    }

    lfi_steps = planner._select_steps(context=lfi_context)
    lfi_tools = [s.get("tool") for s in lfi_steps]
    ffuf_lfi_steps = [s for s in lfi_steps if s.get("tool") == "ffuf" and s.get("reason") == "LFI_TRAVERSAL_VALIDATION"]

    assert "ffuf" in lfi_tools
    assert len(ffuf_lfi_steps) >= 1
    assert ffuf_lfi_steps[0]["impact_class"] == "DESTRUCTIVE"
    assert "FUZZ" in ffuf_lfi_steps[0]["target"]
    assert "-w" in ffuf_lfi_steps[0].get("arguments", [])

    # 3. Test Directory / Unlinked route gap -> ffuf directory discovery candidate
    content_context = {
        "target": "https://server.vulnapp.id/mutillidae/",
        "technologies": ["PHP", "Apache"],
        "endpoints": ["https://server.vulnapp.id/mutillidae/"],
        "findings": [
            {
                "finding_id": "FH-2026-003",
                "title": "Unlinked Admin Surface",
                "vulnerability": "Unlinked Content Discovery",
                "status": "HYPOTHESIS",
                "endpoint": "https://server.vulnapp.id/mutillidae/",
            }
        ],
        "tested_vectors": [],
    }

    content_steps = planner._select_steps(context=content_context)
    ffuf_content_steps = [s for s in content_steps if s.get("tool") == "ffuf" and s.get("reason") == "CONTENT_DISCOVERY_FUZZING"]

    assert len(ffuf_content_steps) >= 1
    assert ffuf_content_steps[0]["impact_class"] == "DESTRUCTIVE"
    assert "-e" in ffuf_content_steps[0].get("arguments", [])


def test_ai_review_evidence_verdict_confirmed(tmp_path: Path, monkeypatch):
    """Test that AI review with VERDICT: CONFIRMED transitions finding to CONFIRMED and attaches evidence."""
    from nyx.core import engagement as core_eng
    from nyx.core import findings as core_findings
    from nyx.ai.manager import AIProviderManager

    core_eng.init_engagement("https://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)
    res = core_findings.create_finding(
        title="Arbitrary File Inclusion",
        endpoint="https://server.vulnapp.id/mutillidae/index.php?page=arbitrary-file-inclusion.php",
        vulnerability="LFI",
        severity="High",
        base_dir=tmp_path,
    )
    fid = res["finding_id"]

    monkeypatch.setattr(
        AIProviderManager,
        "generate",
        lambda self, prompt, **kwargs: "VERDICT: CONFIRMED\nREASONING: The response body contains verified Linux /etc/passwd entries (root:x:0:0) demonstrating root system file disclosure.",
    )

    review_res = core_findings.review_finding_evidence(
        finding_id_or_data=fid,
        tool_name="ffuf",
        tool_output={"results": [{"url": "https://server.vulnapp.id/mutillidae/index.php?page=../../../../etc/passwd", "status": 200, "body": "root:x:0:0:root:/root:/bin/bash"}]},
        base_dir=tmp_path,
    )

    assert review_res["verdict"] == "CONFIRMED"
    assert review_res["new_status"] == "CONFIRMED"

    updated = core_findings.get_finding(fid, base_dir=tmp_path)
    assert updated["status"] == "CONFIRMED"
    assert updated["ai_review"]["verdict"] == "CONFIRMED"
    assert "root:x:0:0" in updated["ai_review"]["reasoning"]


def test_ai_review_evidence_verdict_false_positive_retains_record(tmp_path: Path, monkeypatch):
    """Test that AI review with VERDICT: LIKELY_FALSE_POSITIVE sets status=REJECTED and does not discard record."""
    from nyx.core import engagement as core_eng
    from nyx.core import findings as core_findings
    from nyx.ai.manager import AIProviderManager

    core_eng.init_engagement("https://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)
    res = core_findings.create_finding(
        title="Arbitrary File Inclusion",
        endpoint="https://server.vulnapp.id/mutillidae/index.php?page=arbitrary-file-inclusion.php",
        vulnerability="LFI",
        severity="High",
        base_dir=tmp_path,
    )
    fid = res["finding_id"]

    monkeypatch.setattr(
        AIProviderManager,
        "generate",
        lambda self, prompt, **kwargs: "VERDICT: LIKELY_FALSE_POSITIVE\nREASONING: The application returns HTTP 200 with generic HTML template boilerplate for any random parameter. No file contents leaked.",
    )

    review_res = core_findings.review_finding_evidence(
        finding_id_or_data=fid,
        tool_name="ffuf",
        tool_output={"results": [{"url": "https://server.vulnapp.id/mutillidae/index.php?page=../../../../etc/passwd", "status": 200}]},
        base_dir=tmp_path,
    )

    assert review_res["verdict"] == "LIKELY_FALSE_POSITIVE"
    assert review_res["new_status"] == "REJECTED"

    updated = core_findings.get_finding(fid, base_dir=tmp_path)
    assert updated["status"] == "REJECTED"
    assert updated["ai_review"]["verdict"] == "LIKELY_FALSE_POSITIVE"
    assert "generic HTML template boilerplate" in updated["ai_review"]["reasoning"]


def test_ai_review_evidence_verdict_needs_more_evidence(tmp_path: Path, monkeypatch):
    """Test that AI review with VERDICT: NEEDS_MORE_EVIDENCE keeps status=HYPOTHESIS."""
    from nyx.core import engagement as core_eng
    from nyx.core import findings as core_findings
    from nyx.ai.manager import AIProviderManager

    core_eng.init_engagement("https://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)
    res = core_findings.create_finding(
        title="Arbitrary File Inclusion",
        endpoint="https://server.vulnapp.id/mutillidae/index.php?page=arbitrary-file-inclusion.php",
        vulnerability="LFI",
        severity="High",
        base_dir=tmp_path,
    )
    fid = res["finding_id"]

    monkeypatch.setattr(
        AIProviderManager,
        "generate",
        lambda self, prompt, **kwargs: "VERDICT: NEEDS_MORE_EVIDENCE\nREASONING: Response code 200 with length difference observed, but response body snippet not provided to confirm actual file contents.",
    )

    review_res = core_findings.review_finding_evidence(
        finding_id_or_data=fid,
        tool_name="ffuf",
        tool_output={"results": [{"url": "https://server.vulnapp.id/mutillidae/index.php?page=../../../../etc/passwd", "status": 200, "length": 4512}]},
        base_dir=tmp_path,
    )

    assert review_res["verdict"] == "NEEDS_MORE_EVIDENCE"
    assert review_res["new_status"] == "HYPOTHESIS"

    updated = core_findings.get_finding(fid, base_dir=tmp_path)
    assert updated["status"] == "HYPOTHESIS"
    assert updated["ai_review"]["verdict"] == "NEEDS_MORE_EVIDENCE"


def test_ffuf_adapter_signature_verification_rejects_generic_html():
    """Test that FfufAdapter signature check rejects generic 200 responses for known files (/etc/passwd, access.log)."""
    from nyx.execution.adapters.ffuf import FfufAdapter

    adapter = FfufAdapter()
    generic_results = {
        "results": [
            {
                "url": "https://server.vulnapp.id/mutillidae/index.php?page=../../../../etc/passwd",
                "status": 200,
                "length": 22213,
                "words": 932,
                "lines": 515,
                "body": "<html><head><title>Mutillidae</title></head><body>Generic Welcome Page</body></html>",
            },
            {
                "url": "https://server.vulnapp.id/mutillidae/index.php?page=../../apache/logs/access.log",
                "status": 200,
                "length": 22213,
                "words": 932,
                "lines": 515,
                "body": "<html><head><title>Mutillidae</title></head><body>Generic Welcome Page</body></html>",
            },
        ]
    }

    parsed = adapter.parse_result(stdout=json.dumps(generic_results), stderr="")
    assert len(parsed["endpoints"]) == 2
    # Must be 0 vulnerabilities at adapter level because signatures failed
    assert len(parsed["vulnerabilities"]) == 0


def test_ffuf_adapter_signature_verification_accepts_valid_passwd_content():
    """Test that FfufAdapter accepts response containing genuine /etc/passwd signature."""
    from nyx.execution.adapters.ffuf import FfufAdapter

    adapter = FfufAdapter()
    valid_lfi = {
        "results": [
            {
                "url": "https://server.vulnapp.id/mutillidae/index.php?page=../../../../etc/passwd",
                "status": 200,
                "length": 1520,
                "words": 35,
                "lines": 28,
                "body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            }
        ]
    }

    parsed = adapter.parse_result(stdout=json.dumps(valid_lfi), stderr="")
    assert len(parsed["vulnerabilities"]) == 1
    assert "passwd" in parsed["vulnerabilities"][0]["endpoint"]


def test_ffuf_adapter_baseline_diffing_rejects_uniform_wildcard_responses():
    """Test that FfufAdapter baseline diffing rejects uniform soft-200 responses."""
    from nyx.execution.adapters.ffuf import FfufAdapter

    adapter = FfufAdapter()
    # 20 uniform results simulating wildcard / template reflection
    uniform_results = {
        "results": [
            {
                "url": f"https://server.vulnapp.id/mutillidae/index.php?page=../../../../etc/passwd{i}",
                "status": 200,
                "length": 22000 + i,
                "words": 932,
                "lines": 515,
            }
            for i in range(20)
        ]
    }

    parsed = adapter.parse_result(stdout=json.dumps(uniform_results), stderr="")
    assert len(parsed["endpoints"]) == 20
    assert parsed["baseline_stats"] is not None
    # All uniform matches must be rejected at the adapter level
    assert len(parsed["vulnerabilities"]) == 0


def test_ffuf_build_command_regex_matcher_enforces_mmode_and_omits_default_mc():
    """Test that FfufAdapter omits default -mc and adds -mmode and when regex matcher -mr is present."""
    from nyx.execution.adapters.ffuf import FfufAdapter

    adapter = FfufAdapter()
    cmd = adapter.build_command(
        target="https://server.vulnapp.id/mutillidae/index.php?page=FUZZ",
        arguments=["-w", "wordlist.txt", "-mr", "root:x:0:0"],
    )

    assert "-mr" in cmd
    assert "root:x:0:0" in cmd
    assert "-mmode" in cmd
    assert cmd[cmd.index("-mmode") + 1] == "and"
    # Default -mc status list must NOT be added when -mr is supplied
    assert "-mc" not in cmd


def test_bridge_candidate_finding_description_uses_conservative_unconfirmed_impact(tmp_path: Path):
    """Test that bridge finding creation generates conservative impact text without asserting unproven leaks."""
    from nyx.execution.bridge import bridge_execution_to_findings
    from nyx.models.execution import ExecutionResult
    from nyx.core import engagement as core_eng
    from nyx.core import findings as core_findings

    core_eng.init_engagement("https://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)

    exec_res = ExecutionResult(
        execution_id="EXEC-TEST99",
        status="COMPLETED",
        target="https://server.vulnapp.id/mutillidae/",
        tool_name="ffuf",
        command=["ffuf"],
        stdout="",
        stderr="",
        exit_code=0,
        artifacts={"parsed": {"vulnerabilities": [{"title": "Verified LFI", "endpoint": "https://server.vulnapp.id/mutillidae/index.php?page=../../../../etc/passwd"}]}},
        metadata={"vulnerabilities": [{"title": "Verified LFI", "endpoint": "https://server.vulnapp.id/mutillidae/index.php?page=../../../../etc/passwd"}]},
    )

    created = bridge_execution_to_findings(exec_res, base_dir=tmp_path)
    assert len(created) == 1
    fid = created[0]

    f_data = core_findings.get_finding(fid, base_dir=tmp_path)
    desc = f_data["description"]

    # Must NOT contain fabricated asserts
    assert "Confirmed credential and sensitive data: leaked" not in desc
    assert "potential" in desc.lower() or "validation in progress" in desc.lower()


def test_delete_finding_removes_from_index_and_disk(tmp_path: Path):
    """Test that delete_finding removes finding record from findings.json and filesystem."""
    from nyx.core import engagement as core_eng
    from nyx.core import findings as core_findings

    core_eng.init_engagement("https://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)
    res = core_findings.create_finding(
        title="Test Finding To Delete",
        endpoint="https://server.vulnapp.id/mutillidae/test",
        vulnerability="Test Vuln",
        base_dir=tmp_path,
    )
    fid = res["finding_id"]

    del_res = core_findings.delete_finding(fid, base_dir=tmp_path)
    assert del_res["status"] == "success"

    all_f = core_findings.list_findings(base_dir=tmp_path).get("findings", [])
    assert all(f.get("finding_id") != fid for f in all_f)
    assert not (tmp_path / ".engagement" / "findings" / fid).exists()


def test_autonomous_loop_halts_mid_run_on_ai_failure_preserving_prior_findings(tmp_path: Path, monkeypatch):
    """Test that if AI fails on iteration 2, iteration 1 results & genuine findings are preserved, and no further steps execute."""
    from nyx.ai.planner import MissionPlanner
    from nyx.core import engagement as core_eng
    from nyx.core import findings as core_findings
    from nyx.ai.manager import AIManager

    core_eng.init_engagement("https://test.local/", reset=True, force=True, base_dir=tmp_path)
    core_eng.add_memory(type_="endpoint", value="https://test.local/api/v1/users", endpoint="https://test.local/api/v1/users", base_dir=tmp_path)
    core_eng.add_memory(type_="endpoint", value="https://test.local/api/v1/admin", endpoint="https://test.local/api/v1/admin", base_dir=tmp_path)

    # Pre-seed a genuine finding from earlier phase
    prior_finding = core_findings.create_finding(
        title="Genuine Validated SQLi",
        endpoint="https://test.local/api/v1/users",
        vulnerability="SQL Injection",
        severity="High",
        base_dir=tmp_path,
    )
    prior_fid = prior_finding["finding_id"]

    call_count = 0

    def mock_analyze(self, ctx, prompt=None, provider_name=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call succeeds with genuine AI decision
            return {
                "selected_index": 0,
                "decision": "proceed",
                "reasoning": "Genuine strategic AI selection based on recon context.",
            }
        else:
            # Second call fails with 429 rate limit
            return {
                "status": "error",
                "error_type": "rate_limit",
                "error": "Groq rate limit exceeded for model (HTTP 429)",
            }

    monkeypatch.setattr(AIManager, "analyze", mock_analyze)

    # Mock execute_step to simulate safe successful execution of step 1
    def mock_exec_step(self, step, target, active_permitted=False):
        return {
            "step": step.get("step"),
            "name": step.get("name"),
            "tool": step.get("tool"),
            "result": {"status": "success", "tool_used": step.get("tool")},
        }

    monkeypatch.setattr(MissionPlanner, "execute_step", mock_exec_step)

    planner = MissionPlanner(base_dir=tmp_path)
    res = planner.run_autonomous_loop("https://test.local/", max_iterations=5)

    # 1. Must report ai_unavailable status
    assert res.get("status") == "ai_unavailable"
    assert res.get("iteration_halted") == 2
    assert res.get("ai_degraded") is True
    assert "Groq rate limit" in str(res.get("error")) or "429" in str(res.get("error"))

    # 2. Must preserve iteration 1 executed results
    assert len(res.get("iterations", [])) == 1
    assert res["iterations"][0]["iteration"] == 1
    assert res["iterations"][0]["result"]["result"]["status"] == "success"

    # 3. Must preserve prior genuine findings
    findings_list = core_findings.list_findings(base_dir=tmp_path).get("findings", [])
    assert any(f.get("finding_id") == prior_fid for f in findings_list)

    # 4. Message must explicitly state halting
    assert "Autonomous mission halted" in res.get("message", "")
    assert "No new findings generated" in res.get("message", "")


def test_autonomous_loop_fails_closed_on_unparseable_ai_response(tmp_path: Path, monkeypatch):
    """Test that an unparseable response from AI halts loop immediately instead of silently falling back."""
    from nyx.ai.planner import MissionPlanner
    from nyx.core import engagement as core_eng
    from nyx.ai.manager import AIManager

    core_eng.init_engagement("https://test.local/", reset=True, force=True, base_dir=tmp_path)
    core_eng.add_memory(type_="endpoint", value="https://test.local/login", endpoint="https://test.local/login", base_dir=tmp_path)

    # Mock analyze returning unparseable text
    monkeypatch.setattr(
        AIManager,
        "analyze",
        lambda self, ctx, prompt=None, provider_name=None: {
            "analysis": "I cannot help with this security query as it is restricted.",
            "recommended_focus": "none",
        }
    )

    planner = MissionPlanner(base_dir=tmp_path)
    res = planner.run_autonomous_loop("https://test.local/", max_iterations=3)

    assert res.get("status") == "ai_unavailable"
    assert res.get("ai_degraded") is True
    assert "Unparseable" in str(res.get("degradation_reason")) or "unparseable" in str(res.get("error")).lower()
    assert len(res.get("iterations", [])) == 0


def test_local_llama_provider_registration_and_info():
    """Test that LocalLlamaProvider is registered under 'local' and 'llama' without breaking default provider."""
    from nyx.ai.manager import AIManager, detect_default_provider
    from nyx.ai.providers import get_provider_class, LocalLlamaProvider

    # Default provider should remain whatever configured (Groq/Gemini), NOT forcibly local
    default_p = detect_default_provider()
    assert default_p in ("groq", "gemini", "openai", "claude", "grok", "local")

    mgr = AIManager()
    prov_local = mgr.get_provider("local")
    prov_llama = mgr.get_provider("llama")

    assert isinstance(prov_local, LocalLlamaProvider)
    assert isinstance(prov_llama, LocalLlamaProvider)
    assert prov_local.provider_name == "local"

    info = prov_local.get_info()
    assert info["type"] == "LocalLlamaProvider"
    assert "endpoint" in info


def test_local_llama_provider_generate_and_json_parsing(monkeypatch):
    """Test LocalLlamaProvider JSON parsing and structured analysis from mock server response."""
    from nyx.ai.providers.local_llama import LocalLlamaProvider

    class MockResponse:
        status_code = 200
        def json(self):
            return {
                "response": '{"selected_index": 0, "decision": "proceed", "reasoning": "LFI verification chosen for PHP stack."}'
            }
        @property
        def text(self):
            return '{"response": "..."}'

    import requests
    monkeypatch.setattr(requests, "post", lambda url, json=None, headers=None, timeout=None: MockResponse())

    prov = LocalLlamaProvider(endpoint_url="http://localhost:8000/chat")
    res = prov.analyze({"target": "https://test.local/", "technologies": ["php"]}, prompt="Select candidate step")

    assert res.get("status") == "success"
    assert res.get("selected_index") == 0
    assert res.get("decision") == "proceed"
    assert "LFI verification" in res.get("reasoning", "")


def test_local_llama_provider_fail_closed_on_unreachable_server(tmp_path: Path, monkeypatch):
    """Test that LocalLlamaProvider fails closed with status ai_unavailable when server is unreachable."""
    from nyx.ai.providers.local_llama import LocalLlamaProvider
    from nyx.ai.planner import MissionPlanner
    from nyx.core import engagement as core_eng

    core_eng.init_engagement("https://test.local/", reset=True, force=True, base_dir=tmp_path)
    core_eng.add_memory(type_="endpoint", value="https://test.local/api", endpoint="https://test.local/api", base_dir=tmp_path)

    import requests
    def mock_failing_post(*args, **kwargs):
        raise requests.exceptions.ConnectionError("Failed to establish a new connection: [Errno 111] Connection refused")

    monkeypatch.setattr(requests, "post", mock_failing_post)

    prov = LocalLlamaProvider(endpoint_url="http://127.0.0.1:9999/chat")
    analyze_res = prov.analyze({"target": "https://test.local/"}, prompt="Select step")

    assert analyze_res.get("status") == "error"
    assert analyze_res.get("error_type") == "connection_refused"
    assert "connection refused" in analyze_res.get("error", "").lower()

    # In autonomous planner loop with --provider local
    planner = MissionPlanner(base_dir=tmp_path)
    loop_res = planner.run_autonomous_loop("https://test.local/", provider_name="local", max_iterations=2)

    assert loop_res.get("status") == "ai_unavailable"
    assert loop_res.get("ai_degraded") is True
    assert len(loop_res.get("iterations", [])) == 0


def test_existing_groq_and_gemini_providers_unaffected():
    """Test that existing Groq and Gemini providers remain registered and operational."""
    from nyx.ai.manager import AIManager
    from nyx.ai.providers import GroqProvider, GeminiProvider

    mgr = AIManager()
    groq_prov = mgr.get_provider("groq")
    gemini_prov = mgr.get_provider("gemini")

    assert isinstance(groq_prov, GroqProvider)
    assert isinstance(gemini_prov, GeminiProvider)
    assert groq_prov.provider_name == "groq"
    assert gemini_prov.provider_name == "gemini"


def test_extract_router_targets_query_parameter_awareness():
    """Test that extract_router_targets correctly extracts sub-resource values from router params."""
    from nyx.core.analysis import extract_router_targets

    url_mutillidae_sqli = "http://server.vulnapp.id/mutillidae/index.php?page=user-info.php&username=admin"
    targets = extract_router_targets(url_mutillidae_sqli)

    assert "/user-info.php" in targets
    assert "page=user-info.php" in targets
    assert "/mutillidae/index.php" in targets

    url_action = "http://app.local/main.do?action=login&tab=security"
    targets_action = extract_router_targets(url_action)
    assert "/login" in targets_action or "action=login" in targets_action


def test_query_router_classification_and_hypotheses_generation(tmp_path: Path):
    """Test that query-routed URLs generate hypotheses for SQLi, Command Injection, XSS, and LFI."""
    from nyx.ai.planner import MissionPlanner
    from nyx.application.analysis_service import AnalysisService
    from nyx.core import engagement as core_eng

    core_eng.init_engagement("http://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)

    test_endpoints = [
        "http://server.vulnapp.id/mutillidae/index.php?page=arbitrary-file-inclusion.php",
        "http://server.vulnapp.id/mutillidae/index.php?page=user-info.php&username=admin",
        "http://server.vulnapp.id/mutillidae/index.php?page=dns-lookup.php&target_host=127.0.0.1",
        "http://server.vulnapp.id/mutillidae/index.php?page=add-to-your-blog.php&blog_entry=test",
        "http://server.vulnapp.id/mutillidae/index.php?page=login.php",
    ]

    analysis_svc = AnalysisService()
    classified = []
    for ep in test_endpoints:
        c_res = analysis_svc.classify_url(ep)
        classified.append({
            "url": ep,
            "category": c_res.get("category"),
            "skills": c_res.get("skills", []),
            "matches": c_res.get("matches", {}),
        })

    planner = MissionPlanner(base_dir=tmp_path)
    planner.ai_manager.generate = lambda prompt, options=None: "### Why This Was Flagged\nTest reasoning\n### Exploitability Conditions\nTest conditions\n### Verification Steps\nTest steps\n### Status\nTest status"
    created_hypo = planner._map_classification_to_hypotheses(
        classified_results=classified,
        target="http://server.vulnapp.id/mutillidae/",
    )

    vulns_created = [
        h.get("finding", {}).get("vulnerability") or h.get("vulnerability")
        for h in created_hypo
    ]
    assert "SQL Injection" in vulns_created
    assert "Command Injection" in vulns_created
    assert "Cross-Site Scripting" in vulns_created
    assert "Local File Inclusion" in vulns_created or "Arbitrary File Upload" in vulns_created
    assert "Authentication Bypass" in vulns_created
    assert len(created_hypo) >= 5


def test_enrich_hypothesis_description_success(tmp_path: Path):
    """Test that enrich_hypothesis_description produces structured 4-section AI technical reasoning."""
    from nyx.core import findings as core_findings
    from nyx.core import engagement as core_eng

    core_eng.init_engagement("https://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)
    f_res = core_findings.create_finding(
        title="SQL Injection Surface on https://server.vulnapp.id/mutillidae?page=show-log.php",
        endpoint="https://server.vulnapp.id/mutillidae?page=show-log.php",
        vulnerability="SQL Injection",
        severity="High",
        base_dir=tmp_path,
    )
    fid = f_res["finding_id"]

    # Mock AI manager returning structured 4-section markdown
    class MockAIManager:
        def generate(self, prompt, options=None):
            return (
                "### Why This Was Flagged\n"
                "The page query parameter specifies a PHP script name for dynamic query execution.\n\n"
                "### Exploitability Conditions\n"
                "Requires input concatenation without prepared statements on the backend MySQL database.\n\n"
                "### Verification Steps\n"
                "1. Run sqlmap -u 'https://server.vulnapp.id/mutillidae?page=show-log.php' --batch\n"
                "2. Check response for syntax errors or time delay differences.\n\n"
                "### Status\n"
                "Unconfirmed hypothesis based on automated pattern matching. Requires empirical validation before confirming impact."
            )

    enr_res = core_findings.enrich_hypothesis_description(fid, base_dir=tmp_path, ai_manager=MockAIManager())
    assert enr_res["status"] == "success"
    assert enr_res["ai_enriched"] is True
    assert "Why This Was Flagged" in enr_res["description"]
    assert "Exploitability Conditions" in enr_res["description"]
    assert "Verification Steps" in enr_res["description"]
    assert "Unconfirmed hypothesis" in enr_res["description"]

    # Check updated finding stored in workspace
    updated_f = core_findings.get_finding(fid, base_dir=tmp_path)
    assert "Why This Was Flagged" in updated_f["description"]


def test_enrich_hypothesis_description_fallback_on_ai_failure(tmp_path: Path):
    """Test that enrich_hypothesis_description falls back cleanly with explicit marker if AI is unavailable."""
    from nyx.core import findings as core_findings
    from nyx.core import engagement as core_eng

    core_eng.init_engagement("https://server.vulnapp.id/mutillidae/", reset=True, force=True, base_dir=tmp_path)
    f_res = core_findings.create_finding(
        title="Cross-Site Scripting on https://server.vulnapp.id/mutillidae?page=add-to-your-blog.php",
        endpoint="https://server.vulnapp.id/mutillidae?page=add-to-your-blog.php",
        vulnerability="Cross-Site Scripting",
        severity="Medium",
        base_dir=tmp_path,
    )
    fid = f_res["finding_id"]

    class FailingAIManager:
        def generate(self, prompt, options=None):
            raise RuntimeError("Groq rate limit exceeded (HTTP 429)")

    enr_res = core_findings.enrich_hypothesis_description(fid, base_dir=tmp_path, ai_manager=FailingAIManager())
    assert enr_res["status"] == "fallback"
    assert enr_res["ai_enriched"] is False
    assert "AI Enrichment" in enr_res["description"]
    assert "Unavailable" in enr_res["description"]
    assert "Groq rate limit exceeded" in enr_res["description"]
    assert "Unconfirmed hypothesis" in enr_res["description"]

    # Check updated finding has fallback marker and no fake content
    updated_f = core_findings.get_finding(fid, base_dir=tmp_path)
    assert "AI Enrichment" in updated_f["description"]
    assert "Unavailable" in updated_f["description"]


def test_approve_agent_action_resumes_autonomous_loop_and_respects_iteration_budget(tmp_path: Path, monkeypatch):
    """Test that approving a pending action automatically resumes run_autonomous_loop and respects iteration budget."""
    from nyx.core import engagement as core_eng
    from nyx.ai.planner import MissionPlanner
    from nyx.ai.manager import AIManager
    from nyx.application.agent_service import AgentService

    monkeypatch.chdir(tmp_path)
    core_eng.init_engagement("http://test-resume.local/", reset=True, force=True, base_dir=tmp_path)
    eng_dir = tmp_path / ".engagement"
    (eng_dir / "endpoints.json").write_text(json.dumps([
        {"url": "http://test-resume.local/api/resource1", "host": "test-resume.local"},
        {"url": "http://test-resume.local/api/resource2", "host": "test-resume.local"}
    ]), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps({"web": ["Express"]}), encoding="utf-8")

    # Mock AI analysis globally across all planner instances in this test
    monkeypatch.setattr(AIManager, "analyze", lambda self, ctx, prompt=None, provider_name=None: {
        "selected_index": 0,
        "decision": "proceed",
        "reasoning": "Step selection",
    })

    # Mock step execution so no live external commands run during unit test
    def mock_exec_step(self, step, target, active_permitted=False):
        reason = step.get("reason", "")
        tool = step.get("tool", "")
        from nyx.core.engagement import add_memory
        if reason:
            add_memory(type_="vector", value=reason.lower(), endpoint=target, result="tested_success", base_dir=self.base_dir)
        return {
            "step": step.get("step"),
            "name": step.get("name"),
            "tool": tool,
            "status": "completed",
            "result": {"status": "success"},
        }

    monkeypatch.setattr(MissionPlanner, "execute_step", mock_exec_step)

    def mock_select(self, ctx):
        tested = [str(v.get("vector") or v.get("value") or "").lower() for v in (ctx.get("tested_vectors") or [])]
        candidates = []
        if "c1_vector" not in tested:
            candidates.append({
                "step": 1,
                "name": "Destructive Candidate 1",
                "action": "validate_1",
                "tool": "nuclei",
                "reason": "c1_vector",
                "impact_class": "DESTRUCTIVE",
                "impact_justification": "Modifies database.",
                "target": "http://test-resume.local/api/resource1",
            })
        if "c2_vector" not in tested:
            candidates.append({
                "step": 2,
                "name": "Non-Destructive Candidate 2",
                "action": "classify_2",
                "tool": "nyx-classify",
                "reason": "c2_vector",
                "impact_class": "NON_DESTRUCTIVE",
                "impact_justification": "Passive mapping.",
                "target": "http://test-resume.local/api/resource1",
            })
        if "c3_vector" not in tested:
            candidates.append({
                "step": 3,
                "name": "Destructive Candidate 3",
                "action": "validate_3",
                "tool": "sqlmap",
                "reason": "c3_vector",
                "impact_class": "DESTRUCTIVE",
                "impact_justification": "Active parameter fuzzing.",
                "target": "http://test-resume.local/api/resource2",
            })
        return candidates

    monkeypatch.setattr(MissionPlanner, "_select_steps", mock_select)

    planner = MissionPlanner(base_dir=tmp_path)

    # 1. Start autonomous mission with max_iterations=5
    first_res = planner.run_autonomous_loop("http://test-resume.local/", active_permitted=True, max_iterations=5)
    assert first_res["status"] == "paused_for_approval"
    assert first_res["current_iteration"] == 1
    assert first_res["pending_step"]["name"] == "Destructive Candidate 1"
    act_id_1 = first_res.get("action_id")
    assert act_id_1 is not None

    # 2. Approve the first destructive step via AgentService
    svc = AgentService(base_dir=tmp_path)
    approve_res = svc.approve_action(act_id_1)
    assert approve_res.is_success is True

    # 3. Confirm the autonomous loop automatically continued to candidate 2 and paused on candidate 3!
    resumed = approve_res.data.get("resumed_loop")
    assert resumed is not None
    assert resumed["status"] == "paused_for_approval"
    assert resumed["current_iteration"] == 3
    assert resumed["pending_step"]["name"] == "Destructive Candidate 3"
    assert resumed["pending_step"]["tool"] == "sqlmap"
    assert len(resumed["iterations"]) == 2


def test_resumed_autonomous_loop_reaches_max_iterations_and_does_not_reset_budget(tmp_path: Path, monkeypatch):
    """Test that resumed autonomous loop stops strictly when max_iterations is reached without resetting budget."""
    from nyx.core import engagement as core_eng
    from nyx.ai.planner import MissionPlanner
    from nyx.ai.manager import AIManager
    from nyx.application.agent_service import AgentService

    monkeypatch.chdir(tmp_path)
    core_eng.init_engagement("http://test-budget.local/", reset=True, force=True, base_dir=tmp_path)
    eng_dir = tmp_path / ".engagement"
    (eng_dir / "endpoints.json").write_text(json.dumps([
        {"url": "http://test-budget.local/api/res", "host": "test-budget.local"}
    ]), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps({"web": ["Express"]}), encoding="utf-8")

    monkeypatch.setattr(AIManager, "analyze", lambda self, ctx, prompt=None, provider_name=None: {
        "selected_index": 0,
        "decision": "proceed",
        "reasoning": "Step selection",
    })

    def mock_exec_step(self, step, target, active_permitted=False):
        reason = step.get("reason", "")
        tool = step.get("tool", "")
        from nyx.core.engagement import add_memory
        if reason:
            add_memory(type_="vector", value=reason.lower(), endpoint=target, result="tested_success", base_dir=self.base_dir)
        return {
            "step": step.get("step"),
            "name": step.get("name"),
            "tool": tool,
            "status": "completed",
            "result": {"status": "success"},
        }

    monkeypatch.setattr(MissionPlanner, "execute_step", mock_exec_step)

    def mock_select_budget(self, ctx):
        tested = [str(v.get("vector") or v.get("value") or "").lower() for v in (ctx.get("tested_vectors") or [])]
        candidates = []
        if "c1_vector" not in tested:
            candidates.append({
                "step": 1,
                "name": "Destructive Candidate 1",
                "action": "validate_1",
                "tool": "nuclei",
                "reason": "c1_vector",
                "impact_class": "DESTRUCTIVE",
                "target": "http://test-budget.local/api/res",
            })
        if "c2_vector" not in tested:
            candidates.append({
                "step": 2,
                "name": "Non-Destructive Candidate 2",
                "action": "classify_2",
                "tool": "nyx-classify",
                "reason": "c2_vector",
                "impact_class": "NON_DESTRUCTIVE",
                "target": "http://test-budget.local/api/res",
            })
        return candidates

    monkeypatch.setattr(MissionPlanner, "_select_steps", mock_select_budget)

    planner = MissionPlanner(base_dir=tmp_path)

    # Start loop with strict max_iterations=2
    first_res = planner.run_autonomous_loop("http://test-budget.local/", active_permitted=True, max_iterations=2)
    assert first_res["status"] == "paused_for_approval"
    assert first_res["current_iteration"] == 1
    act_id = first_res.get("action_id")

    # Approve step 1. Next start iteration is 2. Iteration 2 executes Candidate 2.
    # Loop finishes at iteration 2 / max_iterations 2 with complete/max_iterations_reached status.
    svc = AgentService(base_dir=tmp_path)
    approve_res = svc.approve_action(act_id)
    assert approve_res.is_success is True

    resumed = approve_res.data.get("resumed_loop")
    assert resumed is not None
    assert resumed["status"] in ("complete", "max_iterations_reached")
    assert len(resumed["iterations"]) == 2


def test_approval_system_stale_cleanup_and_timestamp(tmp_path: Path):
    """Test that ApprovalSystem sets created_at timestamp and cleans up stale/orphaned actions."""
    from nyx.agent.approval import ApprovalSystem
    from nyx.core import engagement as core_eng

    core_eng.init_engagement("http://cleanup-test.local", reset=True, force=True, base_dir=tmp_path)
    app = ApprovalSystem(base_dir=tmp_path)

    # 1. Submit action
    act1 = app.submit_for_approval({
        "action_id": "ACT-TEST01",
        "target": "http://cleanup-test.local/api",
        "action": "validate",
        "current_iteration": 3,
        "max_iterations": 10,
    })
    act2 = app.submit_for_approval({
        "action_id": "ACT-TEST02",
        "target": "http://other-target.local/api",
        "action": "validate",
        "current_iteration": 1,
        "max_iterations": 10,
    })

    pending = app.get_pending_approvals()
    assert len(pending) == 2
    act1_rec = next(a for a in pending if a["action_id"] == "ACT-TEST01")
    assert "created_at" in act1_rec
    assert act1_rec["current_iteration"] == 3

    # 2. Expire stale actions for cleanup-test.local target
    expired_cnt = app.expire_stale_approvals(target="http://cleanup-test.local", reason="New mission started")
    assert expired_cnt == 1

    remaining = app.get_pending_approvals()
    assert len(remaining) == 1
    assert remaining[0]["action_id"] == "ACT-TEST02"


















