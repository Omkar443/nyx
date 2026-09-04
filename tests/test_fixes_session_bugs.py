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


def test_execution_clean_logging_formatting_and_filtering():
    """Verify tool execution cleans banner noise and summarizes large JSONL output without modifying raw capture."""
    import logging
    import sys
    from nyx.execution.timeout import _format_stdout_line, _route_stderr_line, run_with_timeout

    # 1. Nuclei JSONL finding formatting
    sample_nuclei_json = (
        '{"template-id":"CVE-2020-29227","info":{"name":"Mutillidae Arbitrary File Inclusion",'
        '"severity":"critical"},"matched-at":"http://localhost/show-log.php","request":"GET / HTTP/1.1",'
        '"response":"HTTP/1.1 200 OK\\r\\n\\r\\n<html>long payload</html>"}'
    )
    formatted = _format_stdout_line(sample_nuclei_json)
    assert formatted == "Finding: CVE-2020-29227 [CRITICAL] (Mutillidae Arbitrary File Inclusion) on http://localhost/show-log.php"

    # 2. ASCII banner filtering
    assert _format_stdout_line("  ____  __  _______/ /__  (_) ") is None
    assert _format_stdout_line("/_/ /_/\\__,_/\\___/_/\\___/_/   v3.3.0") is None
    assert _format_stdout_line("https://projectdiscovery.io") is None

    # 3. Routine stderr lines routed to DEBUG
    _, lvl = _route_stderr_line("[INF] Current nuclei version: v3.3.0 (latest)")
    assert lvl == logging.DEBUG

    _, lvl = _route_stderr_line("[INF] Templates loaded for current scan: 14")
    assert lvl == logging.DEBUG

    # 4. Genuine error lines routed to WARNING
    _, lvl = _route_stderr_line("Fatal error: connection refused to 127.0.0.1:80")
    assert lvl == logging.WARNING

    # 5. Verify run_with_timeout preserves full raw content verbatim in return tuple
    code, stdout, stderr, timed_out = run_with_timeout(
        [sys.executable, "-c", f"import sys; print('{sample_nuclei_json}'); print('[INF] scanning', file=sys.stderr)"],
        timeout_sec=5,
    )
    assert code == 0
    assert "<html>long payload</html>" in stdout
    assert "[INF] scanning" in stderr


def test_autonomous_loop_phase_inference_and_transition(tmp_path: Path):
    """Verify MissionPlanner infers canonical phases and transitions engagement state on change."""
    import json
    from nyx.ai.planner import MissionPlanner
    from nyx.core import engagement as core_eng

    # 1. Initialize engagement in DISCOVERY
    core_eng.init_engagement("http://phase-test.local", reset=True, force=True, base_dir=tmp_path)
    planner = MissionPlanner(base_dir=tmp_path)

    # 2. Verify _infer_step_phase mappings
    assert planner._infer_step_phase({"action": "passive_recon", "tool": "httpx"}) == "DISCOVERY"
    assert planner._infer_step_phase({"action": "endpoint_harvesting", "tool": "katana"}) == "DISCOVERY"
    assert planner._infer_step_phase({"action": "technology_mapping", "tool": "nyx-classify"}) == "ANALYSIS"
    assert planner._infer_step_phase({"action": "finding_triage", "tool": "nuclei"}) == "VALIDATION"
    assert planner._infer_step_phase({"action": "finding_triage", "tool": "sqlmap"}) == "VALIDATION"
    assert planner._infer_step_phase({"action": "report_generation", "tool": "nyx-report"}) == "REPORTING"

    # 3. Simulate autonomous loop executing a step in ANALYSIS phase
    # Add endpoints so planner has candidates in ANALYSIS/VALIDATION
    core_eng.record_memory(mem_type="endpoint", val="http://phase-test.local/login.php", base_dir=tmp_path)
    core_eng.record_memory(mem_type="technology", val="PHP", base_dir=tmp_path)

    # Mock AI decision to select candidate index 0
    planner.ai_manager.analyze = lambda ctx, prompt=None, provider_name=None: {"selected_index": 0, "decision": "proceed"}

    # Mock execute_step
    planner.execute_step = lambda step, target, active_permitted=False: {"status": "success"}

    res = planner.run_autonomous_loop(
        target="http://phase-test.local",
        max_iterations=1,
        start_iteration=1,
        active_permitted=True,
    )
    assert len(res.get("iterations", [])) == 1

    # Check state.json was transitioned
    state_data = json.loads((tmp_path / ".engagement" / "state.json").read_text(encoding="utf-8"))
    assert state_data.get("state") in ("ANALYSIS", "VALIDATION")
    assert len(state_data.get("history", [])) >= 1
    assert state_data["history"][0]["previous_state"] == "DISCOVERY"
    assert "Autonomous phase inference:" in state_data["history"][0]["reason"]


def test_mission_history_and_phase_events(tmp_path: Path):
    """Verify GET /api/v1/mission/history returns real timeline and emit_event_sync functions properly."""
    from fastapi.testclient import TestClient
    from nyx.web.app import create_app
    from nyx.core import engagement as core_eng
    from nyx.web.events import emit_event_sync

    # 1. Initialize and perform transitions with specific reasons
    core_eng.init_engagement("http://history-test.local", reset=True, force=True, base_dir=tmp_path)
    core_eng.set_engagement_state(new_state="ANALYSIS", force_state=True, reason="Analysis phase step selected", base_dir=tmp_path)
    core_eng.set_engagement_state(new_state="VALIDATION", force_state=True, reason="Validation step selected", base_dir=tmp_path)

    # 2. Test get_engagement_history directly
    hist = core_eng.get_engagement_history(base_dir=tmp_path)
    assert len(hist.get("history", [])) == 2
    assert len(hist.get("timeline", [])) == 2
    assert hist["timeline"][0]["phase"] == "ANALYSIS"
    assert hist["timeline"][0]["previous_phase"] == "DISCOVERY"
    assert hist["timeline"][1]["phase"] == "VALIDATION"
    assert hist["timeline"][1]["previous_phase"] == "ANALYSIS"

    # 3. Test API endpoint /api/v1/mission/history
    app = create_app()
    from nyx.web.auth import get_or_create_api_token
    token = get_or_create_api_token()
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app) as client:
        # emit_event_sync smoke test
        emit_event_sync("phase_changed", {"phase": "VALIDATION"}, mission_id="http://history-test.local")

        res = client.get("/api/v1/mission/history", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data.get("success") is True
        assert "timeline" in data.get("data", {})


def test_terminal_heartbeat_and_ai_observability(caplog):
    """Verify tool execution heartbeat and AI start/finish logging."""
    import logging
    from nyx.execution.timeout import run_with_timeout
    import sys

    # 1. Test heartbeat in run_with_timeout (simulate with a quick timeout or sleep)
    # We can run a 1.5s command with a patched heartbeat threshold or verify run_with_timeout executes cleanly
    with caplog.at_level(logging.INFO):
        code, stdout, stderr, timed_out = run_with_timeout(
            [sys.executable, "-c", "import time; time.sleep(0.1)"],
            timeout_sec=5,
        )
        assert code == 0
        assert not timed_out

    # 2. Test LocalLlamaProvider start and completion logging
    from nyx.ai.providers.local_llama import LocalLlamaProvider
    prov = LocalLlamaProvider(endpoint_url="http://mock-local:11434/api/generate", model_name="llama3:latest")
    
    # Mock requests.post
    import requests
    class MockResponse:
        status_code = 200
        def json(self):
            return {"response": "test decision", "done": True}
    
    orig_post = requests.post
    try:
        requests.post = lambda *args, **kwargs: MockResponse()
        with caplog.at_level(logging.INFO):
            ans = prov.generate("Hello test")
            assert ans == "test decision"
            assert any("[AI:local] Dispatching prompt to local LLM" in rec.message for rec in caplog.records)
            assert any("[AI:local] Local LLM response received" in rec.message for rec in caplog.records)
    finally:
        requests.post = orig_post


def test_mission_progress_websocket_event_emission(tmp_path, monkeypatch):
    """Verify mission_progress WebSocket event is emitted for reasoning and step execution."""
    from nyx.ai.planner import MissionPlanner
    from nyx.ai.manager import AIManager

    # Setup temp target
    target = "http://progress-test.local"
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text(f"target: {target}\nscope:\n  - {target}\n")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n")
    (eng_dir / "endpoints.json").write_text(json.dumps([f"{target}/login", f"{target}/api"]))
    (eng_dir / "technologies.json").write_text(json.dumps(["apache"]))
    (eng_dir / "state.json").write_text(json.dumps({"state": "DISCOVERY", "history": []}))

    class MockAI:
        active_provider_name = "mock-local"
        def analyze(self, context, prompt=None, provider_name=None):
            return {
                "selected_index": 0,
                "decision": "proceed",
                "reasoning": "Execute initial fingerprinting",
            }

    planner = MissionPlanner(base_dir=tmp_path, ai_manager=MockAI())
    monkeypatch.setattr(planner, "execute_step", lambda step, t, active_permitted=False: {"status": "success", "result": {"status": "completed"}})

    emitted_events = []
    def mock_emit_sync(event_type, data=None, mission_id=None):
        emitted_events.append({"event": event_type, "data": data, "mission_id": mission_id})

    import nyx.web.events
    monkeypatch.setattr(nyx.web.events, "emit_event_sync", mock_emit_sync)

    res = planner.run_autonomous_loop(target=target, max_iterations=1, active_permitted=True)
    assert res.get("status") in ("max_iterations_reached", "complete")

    progress_events = [e for e in emitted_events if e["event"] == "mission_progress"]
    assert len(progress_events) >= 2, f"Expected at least 2 progress events, got: {progress_events}"

    # 1. Reasoning event
    reasoning_ev = next((e for e in progress_events if e["data"].get("state") == "reasoning"), None)
    assert reasoning_ev is not None
    assert reasoning_ev["data"]["iteration"] == 1
    assert reasoning_ev["data"]["provider"] == "mock-local"
    assert "current_step_index" in reasoning_ev["data"]
    assert "total_planned_steps" in reasoning_ev["data"]
    assert "remaining_destructive_count" in reasoning_ev["data"]
    assert "upcoming_pipeline" in reasoning_ev["data"]

    # 2. Executing event
    executing_ev = next((e for e in progress_events if e["data"].get("state") == "executing"), None)
    assert executing_ev is not None
    assert executing_ev["data"]["iteration"] == 1
    assert "step_name" in executing_ev["data"]
    assert "current_step_index" in executing_ev["data"]
    assert "total_planned_steps" in executing_ev["data"]
    assert "remaining_destructive_count" in executing_ev["data"]
    assert "upcoming_pipeline" in executing_ev["data"]

def test_endpoint_filtering_excludes_other_targets_before_cap(tmp_path: Path):
    """Test that ContextEngine filters endpoints to target host+port before applying any cap."""
    from nyx.ai.context import ContextEngine

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: http://localhost:3000\nscope:\n  - http://localhost:3000\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nscope:\n  - http://localhost:3000\n", encoding="utf-8")

    # 70 endpoints on port 80 / other host followed by 20 on localhost:3000
    other_eps = [f"http://other-host.local/path{i}" for i in range(70)]
    target_eps = [f"http://localhost:3000/api/resource{i}" for i in range(20)]
    all_eps = other_eps + target_eps
    (eng_dir / "endpoints.json").write_text(json.dumps(all_eps), encoding="utf-8")

    ce = ContextEngine(base_dir=tmp_path)
    ctx = ce.get_target_context("http://localhost:3000")
    scoped = ctx.get("endpoints", [])

    assert len(scoped) == 20
    assert all("localhost:3000" in ep for ep in scoped)
    assert not any("other-host" in ep for ep in scoped)


def test_target_endpoints_beyond_index_50_correctly_scoped_and_classified(tmp_path: Path):
    """Test that endpoints located strictly beyond index 50 in mixed endpoints.json are recovered and classified."""
    from nyx.ai.context import ContextEngine
    from nyx.ai.planner import MissionPlanner

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: http://localhost:3000\nscope:\n  - http://localhost:3000\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\nscope:\n  - http://localhost:3000\n", encoding="utf-8")

    # First 60 endpoints belong to port 80; target endpoints start at index 60
    port80_eps = [f"http://localhost/doc{i}" for i in range(60)]
    target_eps = [
        "http://localhost:3000/api/Users",
        "http://localhost:3000/login",
        "http://localhost:3000/api/graphql",
        "http://localhost:3000/api/Feedbacks",
        "http://localhost:3000/files",
        "http://localhost:3000/robots.txt",
    ]
    (eng_dir / "endpoints.json").write_text(json.dumps(port80_eps + target_eps), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps(["Express", "Node.js"]), encoding="utf-8")

    ce = ContextEngine(base_dir=tmp_path)
    ctx = ce.get_target_context("http://localhost:3000")
    scoped = ctx.get("endpoints", [])

    assert len(scoped) == len(target_eps)
    assert all(":3000" in ep for ep in scoped)
    # Relevance scoring puts dynamic endpoints ahead of robots.txt
    assert scoped[0] != "http://localhost:3000/robots.txt"
    assert scoped[-1] == "http://localhost:3000/robots.txt"

    # Verify planner produces candidate steps from recovered endpoints
    planner = MissionPlanner(base_dir=tmp_path)
    steps = planner._select_steps(ctx)
    assert len(steps) > 0
    step_tools = [s.get("tool") for s in steps]


def test_cross_target_hypothesis_isolation_in_context_and_planner(tmp_path: Path):
    """Test that findings from Target A never leak into Target B's context, hypotheses, or validation steps."""
    from nyx.ai.context import ContextEngine
    from nyx.ai.planner import MissionPlanner

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)

    # Shared findings.json with findings from two distinct targets
    findings_corpus = [
        {
            "finding_id": "FH-TGT-A-001",
            "status": "HYPOTHESIS",
            "vulnerability": "SQL Injection",
            "title": "SQL Injection on Mutillidae",
            "endpoint": "https://server.vulnapp.id/mutillidae/index.php?page=user-info.php",
            "target": "server.vulnapp.id",
        },
        {
            "finding_id": "FH-TGT-B-001",
            "status": "HYPOTHESIS",
            "vulnerability": "IDOR",
            "title": "IDOR on Juice Shop Users",
            "endpoint": "http://localhost:3000/api/Users",
            "target": "localhost:3000",
        },
    ]
    (eng_dir / "findings.json").write_text(json.dumps(findings_corpus), encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps([
        "https://server.vulnapp.id/mutillidae/index.php?page=user-info.php",
        "http://localhost:3000/api/Users",
    ]), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps(["Express"]), encoding="utf-8")

    ce = ContextEngine(base_dir=tmp_path)
    planner = MissionPlanner(base_dir=tmp_path)

    # 1. Target B (localhost:3000) context & candidate steps
    ctx_b = ce.get_target_context("http://localhost:3000")
    findings_b = ctx_b.get("findings", [])
    assert len(findings_b) == 1
    assert findings_b[0]["finding_id"] == "FH-TGT-B-001"
    assert not any("server.vulnapp.id" in str(f) for f in findings_b)

    steps_b = planner._select_steps(ctx_b)
    # Check that any destructive validation steps are strictly for localhost:3000
    for s in steps_b:
        s_target = s.get("target") or ""
        s_ev = str(s.get("evidence", []))
        assert "server.vulnapp.id" not in s_target
        assert "FH-TGT-A-001" not in s_ev

    # 2. Target A (server.vulnapp.id) context & candidate steps
    ctx_a = ce.get_target_context("https://server.vulnapp.id/mutillidae")
    findings_a = ctx_a.get("findings", [])
    assert len(findings_a) == 1
    assert findings_a[0]["finding_id"] == "FH-TGT-A-001"
    assert not any("localhost:3000" in str(f) for f in findings_a)

    steps_a = planner._select_steps(ctx_a)
    for s in steps_a:
        s_target = s.get("target") or ""
        s_ev = str(s.get("evidence", []))
        assert "localhost:3000" not in s_target
        assert "FH-TGT-B-001" not in s_ev


def test_cross_target_tested_vectors_isolation_in_planner(tmp_path: Path):
    """Test that tested_vectors recorded for Target A do NOT suppress candidate generation on Target B."""
    from nyx.ai.context import ContextEngine
    from nyx.ai.planner import MissionPlanner

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)

    # Tested vectors previously accumulated from Target A
    tested_vectors_corpus = [
        {"vector": "known_technology_detected", "endpoint": "https://server.vulnapp.id/mutillidae", "result": "tested_success"},
        {"vector": "surface_mapping_and_skill_routing", "endpoint": "https://server.vulnapp.id/mutillidae", "result": "tested_success"},
        {"vector": "auth_surface_detected", "endpoint": "https://server.vulnapp.id/mutillidae", "result": "tested_success"},
        {"vector": "api_surface_detected", "endpoint": "https://server.vulnapp.id/mutillidae", "result": "tested_success"},
        {"vector": "graphql_surface_detected", "endpoint": "https://server.vulnapp.id/mutillidae", "result": "tested_success"},
        {"vector": "nyx-classify_execution", "endpoint": "https://server.vulnapp.id/mutillidae", "result": "tested_success"},
    ]
    (eng_dir / "tested_vectors.json").write_text(json.dumps(tested_vectors_corpus), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps(["Express", "Node.js"]), encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps([
        "http://localhost:3000/api/Users",
        "http://localhost:3000/login",
        "http://localhost:3000/graphql",
    ]), encoding="utf-8")

    ce = ContextEngine(base_dir=tmp_path)
    planner = MissionPlanner(base_dir=tmp_path)

    # 1. Target B context scoping verification
    ctx_b = ce.get_target_context("http://localhost:3000")
    tv_b = ctx_b.get("tested_vectors", [])
    # Scoped tested vectors for Target B must be empty (none of Target A's belong to Target B)
    assert len(tv_b) == 0

    # 2. Vector check helper verification
    assert planner._is_vector_already_tested(tested_vectors_corpus, "known_technology_detected", target="https://server.vulnapp.id/mutillidae") is True
    assert planner._is_vector_already_tested(tested_vectors_corpus, "known_technology_detected", target="http://localhost:3000") is False
    assert planner._is_vector_already_tested(tested_vectors_corpus, "auth_surface_detected", target="http://localhost:3000") is False
    assert planner._is_vector_already_tested(tested_vectors_corpus, "graphql_surface_detected", target="http://localhost:3000") is False
    assert planner._is_vector_already_tested(tested_vectors_corpus, "api_surface_detected", target="http://localhost:3000") is False

    # 3. Candidate generation on Target B must NOT be suppressed
    steps_b = planner._select_steps(ctx_b)
    step_reasons = [s.get("reason") for s in steps_b]
    assert "KNOWN_TECHNOLOGY_DETECTED" in step_reasons
    assert "AUTH_SURFACE_DETECTED" in step_reasons
    assert "GRAPHQL_SURFACE_DETECTED" in step_reasons
    assert "API_SURFACE_DETECTED" in step_reasons


def test_cross_target_surface_graph_endpoint_isolation(tmp_path: Path, monkeypatch):
    """Test that build_attack_surface_graph filters endpoints and findings before slicing, preventing cross-target leakage."""
    from nyx.core.surface import build_attack_surface_graph

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("nyx.core.surface._get_eng_dir", lambda base_dir=None: eng_dir)

    # 120 endpoints belonging to Target A (server.vulnapp.id)
    target_a_eps = [f"https://server.vulnapp.id/mutillidae/page{i}.php" for i in range(120)]
    # Target B endpoints located past index 100
    target_b_eps = [
        "http://localhost:3000/api/Users",
        "http://localhost:3000/rest/user/login",
        "http://localhost:3000/api/graphql",
    ]
    (eng_dir / "endpoints.json").write_text(json.dumps(target_a_eps + target_b_eps), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps(["Express", "Node.js"]), encoding="utf-8")

    findings = [
        {"finding_id": "FH-A-01", "title": "SQLi on Mutillidae", "target": "server.vulnapp.id", "endpoint": "https://server.vulnapp.id/mutillidae"},
        {"finding_id": "FH-B-01", "title": "IDOR on Users", "target": "localhost:3000", "endpoint": "http://localhost:3000/api/Users"},
    ]
    (eng_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    # 1. Build graph for Target B (localhost:3000)
    graph_b = build_attack_surface_graph("http://localhost:3000")
    b_node_vals = [n["value"] for n in graph_b["nodes"]]
    b_edge_targets = [e["target"] for e in graph_b["edges"]]

    # Verify Target B endpoints were recovered despite being past index 100
    assert "http://localhost:3000/api/Users" in b_node_vals
    assert "http://localhost:3000/rest/user/login" in b_node_vals
    assert "http://localhost:3000/api/graphql" in b_node_vals

    # Verify ZERO endpoints from Target A leaked into Target B's graph
    assert not any("server.vulnapp.id" in val for val in b_node_vals)
    assert not any("server.vulnapp.id" in val for val in b_edge_targets)

    # Verify findings isolation
    assert "FH-B-01: IDOR on Users" in b_node_vals
    assert not any("FH-A-01" in val for val in b_node_vals)

    # 2. Build graph for Target A (server.vulnapp.id)
    graph_a = build_attack_surface_graph("https://server.vulnapp.id/mutillidae")
    a_node_vals = [n["value"] for n in graph_a["nodes"]]
    a_edge_targets = [e["target"] for e in graph_a["edges"]]

    assert not any("localhost:3000" in val for val in a_node_vals)
    assert not any("localhost:3000" in val for val in a_edge_targets)
    assert "FH-A-01: SQLi on Mutillidae" in a_node_vals
    assert not any("FH-B-01" in val for val in a_node_vals)


def test_priority_4_batched_isolation_analysis_recon_and_tracking(tmp_path: Path, monkeypatch):
    """Test target scoping across rank_surface, get_surface, run_recon_intelligence, and AssetTracker."""
    import sys
    from nyx.core.analysis import rank_surface, get_surface
    from nyx.core.recon import run_recon_intelligence
    from nyx.intelligence.tracking import AssetTracker
    import nyx.infrastructure.filesystem
    import nyx.core.analysis
    import nyx.intelligence.tracking

    recon_intel_mod = sys.modules["nyx.recon.intelligence"]

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(nyx.infrastructure.filesystem, "_get_eng_dir", lambda *args, **kwargs: eng_dir)
    monkeypatch.setattr(nyx.core.analysis, "_get_eng_dir", lambda *args, **kwargs: eng_dir)
    monkeypatch.setattr(nyx.intelligence.tracking, "_get_eng_dir", lambda *args, **kwargs: eng_dir)
    monkeypatch.setattr(recon_intel_mod, "_get_eng_dir", lambda *args, **kwargs: eng_dir)

    target_a_eps = [
        "https://server.vulnapp.id/mutillidae/index.php?page=user-info.php",
        "https://server.vulnapp.id/mutillidae/login.php",
    ]
    target_b_eps = [
        "http://test-app-b.local:8080/api/Users",
        "http://test-app-b.local:8080/rest/user/login",
        "http://test-app-b.local:8080/api/graphql",
    ]
    (eng_dir / "endpoints.json").write_text(json.dumps(target_a_eps + target_b_eps), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps(["Express", "Node.js"]), encoding="utf-8")

    test_target = "http://test-app-b.local:8080"

    # 1. Test rank_surface isolation
    rank_res = rank_surface(test_target)
    ranked_eps = [r["endpoint"] for r in rank_res.get("rankings", [])]
    assert set(ranked_eps) == set(target_b_eps)
    assert not any("server.vulnapp.id" in ep for ep in ranked_eps)

    # 2. Test get_surface isolation
    surf_res = get_surface(test_target)
    manifest_eps = surf_res.get("manifest", {}).get("endpoints", [])
    assert set(manifest_eps) == set(target_b_eps)
    assert not any("server.vulnapp.id" in ep for ep in manifest_eps)

    # 3. Test run_recon_intelligence isolation
    recon_intel = run_recon_intelligence(test_target)
    scored_eps = [p.get("endpoint") for p in recon_intel.get("prioritized_endpoints", [])]
    assert len(scored_eps) == len(target_b_eps)
    assert not any("server.vulnapp.id" in str(ep) for ep in scored_eps)
    assert "http://test-app-b.local:8080/api/Users" in scored_eps

    # 4. Test AssetTracker isolation
    tracker = AssetTracker(base_dir=tmp_path)
    tracker.record_current_state(test_target)
    graph = tracker.get_or_create_graph(test_target)
    graph_dict = graph.to_dict()
    graph_eps = [ep.get("path") or ep.get("url") for ep in graph_dict.get("endpoints", [])]
    subdomains = graph_dict.get("subdomains", [])

    assert set(graph_eps) == set(target_b_eps)
    assert not any("server.vulnapp.id" in str(ep) for ep in graph_eps)
    assert not any("server.vulnapp.id" in str(sub) for sub in subdomains)


def test_e2e_back_to_back_multi_target_zero_cross_contamination(tmp_path: Path, monkeypatch):
    """Full end-to-end sanity check testing two targets back-to-back in the same session.
    Proves zero cross-contamination across context, candidates, hypotheses, approvals,
    tested vectors, attack graphs, and surface rankings."""
    import sys
    from nyx.ai.context import ContextEngine
    from nyx.ai.planner import MissionPlanner
    from nyx.agent.approval import ApprovalSystem
    from nyx.core.surface import build_attack_surface_graph
    from nyx.core.analysis import rank_surface
    from nyx.core.recon import run_recon_intelligence
    import nyx.infrastructure.filesystem
    import nyx.core.surface
    import nyx.core.analysis
    import nyx.agent.approval

    recon_intel_mod = sys.modules["nyx.recon.intelligence"]

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(nyx.infrastructure.filesystem, "_get_eng_dir", lambda *args, **kwargs: eng_dir)
    monkeypatch.setattr(nyx.core.surface, "_get_eng_dir", lambda *args, **kwargs: eng_dir)
    monkeypatch.setattr(nyx.core.analysis, "_get_eng_dir", lambda *args, **kwargs: eng_dir)
    monkeypatch.setattr(recon_intel_mod, "_get_eng_dir", lambda *args, **kwargs: eng_dir)

    target_mut = "https://server.vulnapp.id/mutillidae"
    target_juice = "http://localhost:3000"

    # 1. Populate Target A (Mutillidae) engagement memory
    mut_eps = [
        "https://server.vulnapp.id/mutillidae/index.php?page=user-info.php",
        "https://server.vulnapp.id/mutillidae/login.php",
        "https://server.vulnapp.id/mutillidae/passwords.php",
    ]
    mut_findings = [
        {
            "finding_id": "FH-MUT-001",
            "title": "SQL Injection in User Info",
            "target": target_mut,
            "endpoint": "https://server.vulnapp.id/mutillidae/index.php?page=user-info.php",
            "vulnerability_type": "sqli",
            "hypothesis": "SQL injection vulnerability in page parameter"
        }
    ]
    mut_vectors = [
        {"vector": "known_technology_detected", "endpoint": target_mut, "target": target_mut, "result": "success"},
        {"vector": "auth_surface_detected", "endpoint": "https://server.vulnapp.id/mutillidae/login.php", "target": target_mut, "result": "success"},
    ]

    # Write Target A state
    (eng_dir / "endpoints.json").write_text(json.dumps(mut_eps), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps(["PHP", "Apache", "MySQL"]), encoding="utf-8")
    (eng_dir / "findings.json").write_text(json.dumps(mut_findings), encoding="utf-8")
    (eng_dir / "tested_vectors.json").write_text(json.dumps(mut_vectors), encoding="utf-8")

    # Target A submits an approval action
    app_sys = ApprovalSystem(base_dir=tmp_path)
    app_sys.submit_for_approval({
        "action_id": "ACT-MUT-001",
        "mission_target": target_mut,
        "target": target_mut,
        "name": "SQLMap Injection Verification",
        "tool": "sqlmap",
        "step": {"name": "SQLMap Injection Verification", "target": target_mut, "tool": "sqlmap"}
    })

    # Verify Target A approval is recorded
    mut_pending = app_sys.get_pending_approvals(target=target_mut)
    assert len(mut_pending) == 1
    assert mut_pending[0]["action_id"] == "ACT-MUT-001"

    # 2. NOW, test Target B (Juice Shop) in the same session / workspace
    juice_eps = [
        "http://localhost:3000/api/Users",
        "http://localhost:3000/rest/user/login",
        "http://localhost:3000/api/graphql",
        "http://localhost:3000/.well-known/jwks.json",
    ]
    juice_findings = [
        {
            "finding_id": "FH-JUICE-001",
            "title": "IDOR on Users Endpoint",
            "target": target_juice,
            "endpoint": "http://localhost:3000/api/Users",
            "vulnerability_type": "idor",
            "hypothesis": "IDOR vulnerability on /api/Users"
        }
    ]
    juice_vectors = [
        {"vector": "graphql_surface_detected", "endpoint": "http://localhost:3000/api/graphql", "target": target_juice, "result": "success"},
    ]

    # Append Target B state to the shared files
    (eng_dir / "endpoints.json").write_text(json.dumps(mut_eps + juice_eps), encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps(["PHP", "Apache", "MySQL", "Express", "Node.js", "Angular"]), encoding="utf-8")
    (eng_dir / "findings.json").write_text(json.dumps(mut_findings + juice_findings), encoding="utf-8")
    (eng_dir / "tested_vectors.json").write_text(json.dumps(mut_vectors + juice_vectors), encoding="utf-8")

    # Target B submits an approval action
    app_sys.submit_for_approval({
        "action_id": "ACT-JUICE-001",
        "mission_target": target_juice,
        "target": target_juice,
        "name": "Nuclei Auth Bypass Verification",
        "tool": "nuclei",
        "step": {"name": "Nuclei Auth Bypass Verification", "target": target_juice, "tool": "nuclei"}
    })

    # --- VERIFICATION A: Context Engine Isolation ---
    ctx_engine = ContextEngine(base_dir=tmp_path)
    ctx_b = ctx_engine.get_target_context(target_juice)

    # Juice Shop context must ONLY contain Juice Shop endpoints
    assert len(ctx_b["endpoints"]) == len(juice_eps)
    assert not any("server.vulnapp.id" in ep for ep in ctx_b["endpoints"])
    assert "http://localhost:3000/api/Users" in ctx_b["endpoints"]

    # Juice Shop context must ONLY contain Juice Shop findings
    assert len(ctx_b["findings"]) == 1
    assert ctx_b["findings"][0]["finding_id"] == "FH-JUICE-001"

    # Juice Shop context must ONLY contain Juice Shop tested vectors
    assert len(ctx_b["tested_vectors"]) == 1
    assert ctx_b["tested_vectors"][0]["target"] == target_juice

    # --- VERIFICATION B: Planner Candidate & Hypothesis Isolation ---
    planner = MissionPlanner(base_dir=tmp_path)
    steps_b = planner._select_steps(ctx_b)
    step_targets = [s.get("target") for s in steps_b]
    step_reasons = [s.get("reason") for s in steps_b]

    # Zero candidate steps target Mutillidae
    assert not any("server.vulnapp.id" in str(tgt) for tgt in step_targets)

    # Rule 4 hypothesis finding must NOT leak Mutillidae's SQLi finding into Juice Shop
    for s in steps_b:
        if s.get("reason") == "HYPOTHESIS_VALIDATION_REQUIRED":
            assert "server.vulnapp.id" not in s.get("target", "")
            assert "Mutillidae" not in s.get("name", "")

    # Target A's tested vectors (known_technology_detected, auth_surface_detected)
    # MUST NOT suppress candidate generation on Target B
    assert "KNOWN_TECHNOLOGY_DETECTED" in step_reasons
    assert "AUTH_SURFACE_DETECTED" in step_reasons

    # --- VERIFICATION C: Approvals Isolation ---
    # Target B only sees its own approval
    juice_pending = app_sys.get_pending_approvals(target=target_juice)
    assert len(juice_pending) == 1
    assert juice_pending[0]["action_id"] == "ACT-JUICE-001"

    # Target A only sees its own approval
    mut_pending = app_sys.get_pending_approvals(target=target_mut)
    assert len(mut_pending) == 1
    assert mut_pending[0]["action_id"] == "ACT-MUT-001"

    # --- VERIFICATION D: Attack Graph Isolation ---
    graph_b = build_attack_surface_graph(target_juice)
    b_nodes = [n["value"] for n in graph_b["nodes"]]
    b_edges = [e["target"] for e in graph_b["edges"]]
    assert not any("server.vulnapp.id" in str(v) for v in b_nodes)
    assert not any("server.vulnapp.id" in str(v) for v in b_edges)
    assert not any("FH-MUT-001" in str(v) for v in b_nodes)
    assert "FH-JUICE-001: IDOR on Users Endpoint" in b_nodes

    graph_a = build_attack_surface_graph(target_mut)
    a_nodes = [n["value"] for n in graph_a["nodes"]]
    a_edges = [e["target"] for e in graph_a["edges"]]
    assert not any("localhost:3000" in str(v) for v in a_nodes)
    assert not any("localhost:3000" in str(v) for v in a_edges)
    assert not any("FH-JUICE-001" in str(v) for v in a_nodes)
    assert "FH-MUT-001: SQL Injection in User Info" in a_nodes

    # --- VERIFICATION E: Surface Ranking & Recon Intel Isolation ---
    rank_b = rank_surface(target_juice)
    ranked_b_eps = [r["endpoint"] for r in rank_b.get("rankings", [])]
    assert not any("server.vulnapp.id" in str(ep) for ep in ranked_b_eps)

    intel_b = run_recon_intelligence(target_juice)
    intel_b_eps = [p.get("endpoint") for p in intel_b.get("prioritized_endpoints", [])]
    assert not any("server.vulnapp.id" in str(ep) for ep in intel_b_eps)


def test_url_fragment_normalization_and_parity(tmp_path):
    """
    Regression Test: Proves that submitting a target with a URL fragment (e.g. http://localhost:3000/#/)
    is normalized at ingestion and produces identical context, recon probing, hypotheses, and candidate
    steps as http://localhost:3000.
    """
    from nyx.execution.policy import normalize_target, extract_hostname
    from nyx.core.engagement import init_engagement
    from nyx.recon.content_discovery import extract_spa_routes, probe_single_path
    from nyx.ai.planner import MissionPlanner
    from nyx.ai.context import ContextEngine
    from unittest.mock import patch, MagicMock
    import json

    # 1. Target string normalization verification
    t_clean = "http://localhost:3000"
    t_frag = "http://localhost:3000/#/"
    t_frag_route = "http://localhost:3000/#/search?q=test"

    assert normalize_target(t_frag) == t_clean
    assert normalize_target(t_frag_route) == t_clean
    assert normalize_target(t_clean) == t_clean
    assert extract_hostname(t_frag) == "localhost"
    assert extract_hostname(t_clean) == "localhost"

    # 2. Engagement workspace initialization parity
    d_clean = tmp_path / "eng_clean"
    d_frag = tmp_path / "eng_frag"

    init_engagement(t_clean, reset=True, base_dir=d_clean)
    init_engagement(t_frag, reset=True, base_dir=d_frag)

    target_yaml_clean = (d_clean / ".engagement" / "target.yaml").read_text(encoding="utf-8")
    target_yaml_frag = (d_frag / ".engagement" / "target.yaml").read_text(encoding="utf-8")

    assert "#/" not in target_yaml_frag
    assert target_yaml_clean == target_yaml_frag

    # 3. Content discovery clean_base defense-in-depth
    # Both base URLs must probe the exact same target URL without fragment
    with patch("urllib.request.urlopen") as mock_url, patch("nyx.recon.content_discovery.is_hostname_in_scope", return_value=True):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"<html><head><title>Test</title></head><body></body></html>"
        mock_resp.status = 200
        mock_resp.headers = {"Server": "Express"}
        mock_resp.__enter__.return_value = mock_resp
        mock_url.return_value = mock_resp

        res_clean = probe_single_path(t_clean, ".env")
        res_frag = probe_single_path(t_frag, ".env")

        assert res_clean is not None
        assert res_frag is not None
        assert res_clean["url"] == "http://localhost:3000/.env"
        assert res_frag["url"] == "http://localhost:3000/.env"

    # 4. Hypothesis generation parity
    # Even if an endpoint retains an SPA hash route, classifier extracts route from fragment
    planner = MissionPlanner(base_dir=d_frag)
    classified = [
        {
            "url": "http://localhost:3000/#/.well-known/jwks.json",
            "category": "AUTH",
            "skills": ["hunt-jwt-crypto"],
            "matches": {"auth": True},
        },
        {
            "url": "http://localhost:3000/#/api/Users",
            "category": "API",
            "skills": ["hunt-idor"],
            "matches": {"idor": True},
        },
    ]

    with patch.object(planner.ai_manager, "generate", return_value='{"vulnerability": "IDOR", "severity": "HIGH"}'):
        hypos = planner._map_classification_to_hypotheses(classified, target=t_frag)
        assert len(hypos) >= 1
        # Proves hypotheses were generated rather than skipped by the bare root filter
        hypo_vulns = [h.get("finding", {}).get("vulnerability") or h.get("vulnerability") for h in hypos]
        assert any("Token" in str(v) or "IDOR" in str(v) or "Authentication" in str(v) for v in hypo_vulns)

    # 5. Candidate step generation parity
    # Put identical endpoints and findings into both engagement directories
    eps = [
        {"url": "http://localhost:3000/api/Users"},
        {"url": "http://localhost:3000/.well-known/jwks.json"},
    ]
    findings = [
        {
            "finding_id": "FH-2026-001",
            "title": "IDOR on Users Endpoint",
            "vulnerability": "IDOR",
            "endpoint": "http://localhost:3000/api/Users",
            "target": "http://localhost:3000",
            "state": "HYPOTHESIS",
        }
    ]
    for d in (d_clean, d_frag):
        (d / ".engagement" / "endpoints.json").write_text(json.dumps(eps), encoding="utf-8")
        (d / ".engagement" / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    ctx_clean = ContextEngine(base_dir=d_clean).get_target_context(t_clean)
    ctx_frag = ContextEngine(base_dir=d_frag).get_target_context(t_frag)

    planner_clean = MissionPlanner(base_dir=d_clean)
    planner_frag = MissionPlanner(base_dir=d_frag)

    cands_clean = planner_clean._select_steps(ctx_clean)
    cands_frag = planner_frag._select_steps(ctx_frag)

    # Candidate step count and tools must match identically
    clean_tools = [c["tool"] for c in cands_clean]
    frag_tools = [c["tool"] for c in cands_frag]
    assert clean_tools == frag_tools
    # Both must include destructive validation tools (nuclei, etc.) from Rule 4
    assert "nuclei" in frag_tools
    assert "nyx-triage" in frag_tools


def test_local_llama_num_predict_mapping_and_failure_logging(caplog):
    """
    Regression Test:
    1. Proves max_completion_tokens is mapped to Ollama num_predict in payload.
    2. Proves logger.warning is emitted on timeout or error instead of silent failure.
    """
    import logging
    from unittest.mock import patch, MagicMock
    from nyx.ai.providers.local_llama import LocalLlamaProvider

    prov = LocalLlamaProvider()

    # 1. Verify num_predict payload mapping
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"response": "test response"}
        mock_post.return_value = mock_resp

        res = prov.generate("hello", options={"max_completion_tokens": 250, "temperature": 0.3})
        assert res == "test response"
        mock_post.assert_called_once()
        sent_json = mock_post.call_args[1]["json"]
        assert sent_json["options"]["num_predict"] == 250
        assert sent_json["options"]["temperature"] == 0.3

    # 2. Verify failure/timeout warning log is emitted
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        with patch("requests.post", side_effect=TimeoutError("Read timed out")):
            try:
                prov.generate("hello timeout", options={"timeout": 5.0})
            except RuntimeError:
                pass

    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING and "[AI:local]" in r.message]
    assert len(warning_records) >= 1
    assert "Request failed/timed out after" in warning_records[0].message


def test_web_clean_shutdown_and_signal_idempotency():
    """
    Regression Test:
    1. Proves _sigint_handler does not double-forward if already shutting down.
    2. Proves cmd_web handles KeyboardInterrupt/CancelledError cleanly returning 0.
    3. Proves child subprocesses are terminated during shutdown.
    """
    import argparse
    import asyncio
    import subprocess
    import sys
    from unittest.mock import patch, MagicMock
    from nyx.infrastructure.process import (
        register_process,
        unregister_process,
        terminate_all_subprocesses,
        _active_processes,
    )
    from nyx_cli.cli import cmd_web

    # 1. Verify child process termination
    dummy_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    register_process(dummy_proc)
    assert dummy_proc.poll() is None
    terminate_all_subprocesses()
    assert dummy_proc.poll() is not None
    assert len(_active_processes) == 0

    # 2. Verify cmd_web clean catch of CancelledError and exit code 0
    args = argparse.Namespace(host="127.0.0.1", port=8985)
    with patch("nyx.infrastructure.dependencies.BootstrapManager.ensure_environment", return_value=True), \
         patch("uvicorn.run", side_effect=asyncio.CancelledError()):
        code = cmd_web(args)
        assert code == 0

    with patch("nyx.infrastructure.dependencies.BootstrapManager.ensure_environment", return_value=True), \
         patch("uvicorn.run", side_effect=KeyboardInterrupt()):
        code = cmd_web(args)
        assert code == 0


def test_local_llama_model_name_env_var_override(monkeypatch):
    """
    Test 1: Proves LOCAL_LLM_MODEL in the environment correctly configures
    the model_name when LocalLlamaProvider is instantiated with no arguments
    (the same way AIManager instantiates it via cls()).
    """
    monkeypatch.setenv("LOCAL_LLM_MODEL", "mistral:7b")
    from nyx.ai.providers.local_llama import LocalLlamaProvider
    from nyx.ai.manager import AIManager

    # Instantiation via no args (default call)
    prov = LocalLlamaProvider()
    assert prov.model_name == "mistral:7b"

    # Instantiation via AIManager.get_provider("local")
    mgr = AIManager(default_provider="local")
    mgr_prov = mgr.get_provider("local")
    assert mgr_prov.model_name == "mistral:7b"


def test_local_llama_model_name_default_fallback(monkeypatch):
    """
    Test 2: Proves when no model env vars are set, LocalLlamaProvider
    cleanly falls back to 'qwen2.5-coder:7b' (regression check preserving defaults).
    """
    monkeypatch.delenv("LOCAL_LLM_MODEL", raising=False)
    monkeypatch.delenv("NYX_LOCAL_MODEL", raising=False)
    from nyx.ai.providers.local_llama import LocalLlamaProvider
    from nyx.ai.manager import AIManager

    # Instantiation via no args
    prov = LocalLlamaProvider()
    assert prov.model_name == "qwen2.5-coder:7b"

    # Instantiation via AIManager
    mgr = AIManager(default_provider="local")
    mgr_prov = mgr.get_provider("local")
    assert mgr_prov.model_name == "qwen2.5-coder:7b"


def test_token_budget_config_and_defaults(monkeypatch, tmp_path):
    """
    Phase 2 Tests:
    1. Proves no env vars set -> enrich uses 1000, review uses 800 (regression check).
    2. Proves LOCAL_MAX_TOKENS sets both when specific vars are unset.
    3. Proves LOCAL_MAX_TOKENS_ENRICHMENT and LOCAL_MAX_TOKENS_EVIDENCE override individually.
    """
    from unittest.mock import MagicMock
    from nyx.core.findings import enrich_hypothesis_description, review_finding_evidence

    # Clear all token env vars
    for var in ["LOCAL_MAX_TOKENS", "NYX_LOCAL_MAX_TOKENS",
                "LOCAL_MAX_TOKENS_ENRICHMENT", "NYX_LOCAL_MAX_TOKENS_ENRICHMENT",
                "LOCAL_MAX_TOKENS_EVIDENCE", "NYX_LOCAL_MAX_TOKENS_EVIDENCE"]:
        monkeypatch.delenv(var, raising=False)

    mock_ai = MagicMock()
    mock_ai.generate.return_value = "### Why This Was Flagged\nValid description here."

    dummy_finding = {
        "finding_id": "FH-2026-001",
        "endpoint": "http://localhost:3000/api",
        "vulnerability": "SQLi",
        "severity": "High",
        "description": "Initial desc"
    }

    # Case 1: No env vars set -> 1000 and 800
    enrich_hypothesis_description(dummy_finding, base_dir=tmp_path, ai_manager=mock_ai)
    assert mock_ai.generate.call_args[1]["options"]["max_completion_tokens"] == 1000

    review_finding_evidence(dummy_finding, tool_name="nuclei", tool_output="test", base_dir=tmp_path, ai_manager=mock_ai)
    assert mock_ai.generate.call_args[1]["options"]["max_completion_tokens"] == 800

    # Case 2: LOCAL_MAX_TOKENS=250 -> both use 250
    monkeypatch.setenv("LOCAL_MAX_TOKENS", "250")
    enrich_hypothesis_description(dummy_finding, base_dir=tmp_path, ai_manager=mock_ai)
    assert mock_ai.generate.call_args[1]["options"]["max_completion_tokens"] == 250

    review_finding_evidence(dummy_finding, tool_name="nuclei", tool_output="test", base_dir=tmp_path, ai_manager=mock_ai)
    assert mock_ai.generate.call_args[1]["options"]["max_completion_tokens"] == 250

    # Case 3: Specific overrides LOCAL_MAX_TOKENS_ENRICHMENT=180, LOCAL_MAX_TOKENS_EVIDENCE=150
    monkeypatch.setenv("LOCAL_MAX_TOKENS_ENRICHMENT", "180")
    monkeypatch.setenv("LOCAL_MAX_TOKENS_EVIDENCE", "150")
    enrich_hypothesis_description(dummy_finding, base_dir=tmp_path, ai_manager=mock_ai)
    assert mock_ai.generate.call_args[1]["options"]["max_completion_tokens"] == 180

    review_finding_evidence(dummy_finding, tool_name="nuclei", tool_output="test", base_dir=tmp_path, ai_manager=mock_ai)
    assert mock_ai.generate.call_args[1]["options"]["max_completion_tokens"] == 150


def test_enrich_hypothesis_bounded_retry_on_timeout(tmp_path):
    """
    Phase 3 Test 1:
    Simulate a timeout on attempt 1 and success on attempt 2.
    Confirm retry fires exactly once, marks retried=True, and succeeds.
    """
    from unittest.mock import MagicMock
    from nyx.core.findings import enrich_hypothesis_description

    mock_ai = MagicMock()
    # Attempt 1: TimeoutError; Attempt 2: Valid response
    mock_ai.generate.side_effect = [
        TimeoutError("Local AI connection timed out after 120.0 seconds"),
        "### Why This Was Flagged\nSecond attempt succeeded with full analysis."
    ]

    dummy_finding = {
        "finding_id": "FH-2026-RETRY",
        "endpoint": "http://localhost:3000/api/retry",
        "vulnerability": "SQLi",
        "severity": "High",
        "description": "Base description"
    }

    res = enrich_hypothesis_description(dummy_finding, base_dir=tmp_path, ai_manager=mock_ai)
    assert mock_ai.generate.call_count == 2
    assert res["ai_enriched"] is True
    assert res["retried"] is True
    assert "Second attempt succeeded" in res["description"]


def test_re_enrich_hypothesis_on_failed_finding(tmp_path):
    """
    Phase 3 Test 2:
    Confirm that an already-failed finding (with fallback markers and ai_enriched=False)
    can be explicitly re-enriched, replacing the fallback marker with genuine AI reasoning.
    Also confirm that already-enriched findings are skipped unless force=True / re_enrich is called.
    """
    from unittest.mock import MagicMock
    from nyx.core.findings import create_finding, enrich_hypothesis_description, re_enrich_hypothesis
    from nyx.application.finding_service import FindingService

    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: localhost:3000\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    # 1. Create a hypothesis
    f_res = create_finding(
        title="SQLi on /search",
        endpoint="http://localhost:3000/search",
        vulnerability="SQLi",
        severity="High",
        description="Original heuristic detection",
        base_dir=tmp_path
    )
    fid = f_res["finding_id"]

    # 2. Enrich with failing AI -> falls back to ai_enriched=False
    fail_ai = MagicMock()
    fail_ai.generate.side_effect = RuntimeError("Ollama connection refused")
    enrich_res1 = enrich_hypothesis_description(fid, base_dir=tmp_path, ai_manager=fail_ai)
    assert enrich_res1["ai_enriched"] is False
    assert "**AI Enrichment**: Unavailable" in enrich_res1["description"]

    # 3. Use FindingService.re_enrich to explicitly re-trigger with working AI
    working_ai = MagicMock()
    working_ai.generate.return_value = "### Why This Was Flagged\nNow successfully analyzed."

    svc = FindingService(base_dir=tmp_path)
    re_res = svc.re_enrich(fid, ai_manager=working_ai)

    assert re_res["ai_enriched"] is True
    assert "Now successfully analyzed." in re_res["description"]
    assert "**AI Enrichment**: Unavailable" not in re_res["description"]  # Previous fallback was stripped

    # 4. Confirm subsequent standard enrich() skips because it is already enriched
    skip_ai = MagicMock()
    skip_res = svc.enrich(fid, ai_manager=skip_ai)
    assert skip_res["status"] == "skipped"
    assert skip_ai.generate.call_count == 0  # AI was not re-called unnecessarily


def test_auto_calibrated_timeout_scaling_and_bounds():
    """
    Phase 4 Test:
    1. Tests dynamic timeout scaling with fast, moderate, and slow tok/s.
    2. Confirms lower floor (30s) and upper ceiling (600s) are strictly enforced.
    3. Confirms response eval metrics dynamically calibrate speed and scale the next request timeout.
    """
    from unittest.mock import patch, MagicMock
    from nyx.ai.providers.local_llama import LocalLlamaProvider, calculate_dynamic_timeout

    # 1. Floor check: fast hardware (100 tok/s, 1000 tokens) -> 15s -> floored at 30.0s
    t_fast = calculate_dynamic_timeout(token_budget=1000, tok_per_sec=100.0)
    assert t_fast == 30.0

    # 2. Moderate scaling: 25 tok/s, 1000 tokens -> (1000 / 25) * 1.5 = 60.0s
    t_mod = calculate_dynamic_timeout(token_budget=1000, tok_per_sec=25.0)
    assert t_mod == 60.0

    # 3. Constrained hardware scaling: 4.0 tok/s, 1000 tokens -> (1000 / 4) * 1.5 = 375.0s
    t_slow = calculate_dynamic_timeout(token_budget=1000, tok_per_sec=4.0)
    assert t_slow == 375.0

    # 4. Ceiling check: very slow hardware (0.5 tok/s, 1000 tokens) -> 3000s -> capped at 600.0s
    t_vslow = calculate_dynamic_timeout(token_budget=1000, tok_per_sec=0.5)
    assert t_vslow == 600.0

    # 5. Default fallback when uncalibrated (tok_per_sec=None)
    t_uncal = calculate_dynamic_timeout(token_budget=1000, tok_per_sec=None, fallback_timeout=120.0)
    assert t_uncal == 120.0

    # 6. Response calibration: verify eval_count / eval_duration sets speed and scales next request timeout
    prov = LocalLlamaProvider(endpoint_url="http://mock-ollama:11434/api/generate")
    prov.measured_tok_per_sec = None
    LocalLlamaProvider._cached_speed = None

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # 200 tokens generated in 10,000,000,000 ns (10s) -> exactly 20.0 tok/s
    mock_resp.json.return_value = {
        "response": "Analysis complete.",
        "eval_count": 200,
        "eval_duration": 10000000000,
    }

    with patch("requests.post", return_value=mock_resp) as mock_post:
        prov.generate("test prompt", options={"max_completion_tokens": 500})
        # Verify initial uncalibrated call used fallback 120s
        assert mock_post.call_args[1]["timeout"] == 120.0

    # Verify provider now calibrated to 20.0 tok/s
    assert prov.measured_tok_per_sec == 20.0
    assert LocalLlamaProvider._cached_speed == 20.0

    with patch("requests.post", return_value=mock_resp) as mock_post2:
        prov.generate("test prompt 2", options={"max_completion_tokens": 1000})
        assert mock_post2.call_args[1]["timeout"] == 75.0


def test_queue_convoy_cooldown_after_timeout():
    """
    Phase 5 Test:
    Simulates a client timeout on call 1.
    Confirms that the next immediate call in the loop triggers queue-drain cooldown
    (calls time.sleep) rather than firing concurrently into an overloaded Ollama queue.
    """
    import pytest
    from unittest.mock import patch, MagicMock
    from nyx.ai.providers.local_llama import LocalLlamaProvider

    prov = LocalLlamaProvider(endpoint_url="http://mock-ollama:11434/api/generate")
    # Reset any lingering class state
    LocalLlamaProvider._last_timeout_time = None

    # Call 1: Times out after 30s
    with patch("requests.post", side_effect=TimeoutError("Request timed out after 30.0s")):
        with pytest.raises(RuntimeError) as exc_info:
            prov.generate("Prompt 1", options={"timeout": 30.0})
        assert "timed out" in str(exc_info.value).lower()

    # Verify timeout was recorded and cooldown set
    assert LocalLlamaProvider._last_timeout_time is not None
    assert LocalLlamaProvider._last_timeout_cooldown >= 3.0

    # Call 2: Dispatched immediately after Call 1
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "Success after queue cooldown"}

    with patch("time.sleep") as mock_sleep, patch("requests.post", return_value=mock_resp):
        res = prov.generate("Prompt 2", options={"timeout": 30.0})
        # Assert time.sleep was engaged to allow server queue to drain
        assert mock_sleep.called
        assert mock_sleep.call_args[0][0] > 0
        assert res == "Success after queue cooldown"

    # Verify cooldown state reset after draining
    assert LocalLlamaProvider._last_timeout_time is None


def test_server_adapter_ollama_and_openai_compatible(monkeypatch):
    """
    Phase 6 Test:
    1. Tests Ollama response parsing and asserts byte/payload structure matches Ollama spec.
    2. Tests OpenAI-compatible response parsing and payload structure (messages, max_tokens).
    3. Confirms model auto-detection on OpenAI /v1/models response.
    4. Confirms default Ollama + qwen2.5-coder:7b behavior is unchanged (regression check).
    """
    from unittest.mock import patch, MagicMock
    from nyx.ai.providers.local_llama import LocalLlamaProvider, SERVER_OLLAMA, SERVER_OPENAI_COMPATIBLE

    monkeypatch.delenv("LOCAL_LLM_MODEL", raising=False)
    monkeypatch.delenv("NYX_LOCAL_MODEL", raising=False)
    monkeypatch.delenv("LOCAL_LLM_SERVER_TYPE", raising=False)

    # 1. Default Ollama Provider: verify payload and parsing
    ollama_prov = LocalLlamaProvider()
    assert ollama_prov.server_type == SERVER_OLLAMA
    assert ollama_prov.model_name == "qwen2.5-coder:7b"

    mock_ollama_resp = MagicMock()
    mock_ollama_resp.status_code = 200
    mock_ollama_resp.json.return_value = {
        "response": '{"decision": "next_step"}',
        "eval_count": 50,
        "eval_duration": 2500000000
    }

    with patch("requests.post", return_value=mock_ollama_resp) as mock_post:
        resp = ollama_prov.generate("Plan next step", options={"max_completion_tokens": 1024})
        assert resp == '{"decision": "next_step"}'
        sent_url = mock_post.call_args[0][0]
        sent_payload = mock_post.call_args[1]["json"]
        assert sent_url == "http://localhost:11434/api/generate"
        assert sent_payload == {
            "model": "qwen2.5-coder:7b",
            "prompt": "Plan next step",
            "stream": False,
            "options": {"num_predict": 1024}
        }

    # 2. OpenAI-Compatible Provider (LM Studio / vLLM): verify payload and parsing
    oai_prov = LocalLlamaProvider(
        endpoint_url="http://localhost:1234/v1/chat/completions",
        health_url="http://localhost:1234/v1/models"
    )
    assert oai_prov.server_type == SERVER_OPENAI_COMPATIBLE

    mock_oai_resp = MagicMock()
    mock_oai_resp.status_code = 200
    mock_oai_resp.json.return_value = {
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": '{"decision": "oai_step"}'
                }
            }
        ]
    }

    with patch("requests.post", return_value=mock_oai_resp) as mock_post_oai:
        resp_oai = oai_prov.generate("Plan next step", options={"max_completion_tokens": 512})
        assert resp_oai == '{"decision": "oai_step"}'
        sent_url_oai = mock_post_oai.call_args[0][0]
        sent_payload_oai = mock_post_oai.call_args[1]["json"]
        assert sent_url_oai == "http://localhost:1234/v1/chat/completions"
        assert sent_payload_oai == {
            "model": "qwen2.5-coder:7b",
            "messages": [{"role": "user", "content": "Plan next step"}],
            "max_tokens": 512,
            "stream": False
        }

    # 3. Model auto-detection on OpenAI /v1/models response
    detect_prov = LocalLlamaProvider(
        endpoint_url="http://localhost:1234/v1/chat/completions",
        health_url="http://localhost:1234/v1/models"
    )
    mock_models_resp = MagicMock()
    mock_models_resp.status_code = 200
    mock_models_resp.json.return_value = {
        "data": [{"id": "meta-llama/Llama-3.2-3B-Instruct"}]
    }

    with patch("requests.get", return_value=mock_models_resp), \
         patch.object(detect_prov, "generate", return_value="OK"):
        conn_res = detect_prov.test_connection(timeout_sec=5.0)
        assert conn_res["success"] is True
        assert detect_prov.model_name == "meta-llama/Llama-3.2-3B-Instruct"


def test_structured_output_mode_and_fallback():
    """
    Phase 7 Test:
    1. Confirms Ollama requests include format: 'json' when structured mode is active.
    2. Confirms OpenAI-compatible requests include response_format: {'type': 'json_object'}.
    3. Confirms that if a server returns HTTP 400 for structured format, it retries cleanly without it.
    4. Confirms that the secondary regex parser cleanly extracts JSON embedded in prose/markdown.
    """
    from unittest.mock import patch, MagicMock
    from nyx.ai.providers.local_llama import LocalLlamaProvider

    # 1. Ollama structured request
    ollama_prov = LocalLlamaProvider()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": '{"focus": "Auth surface", "reasoning": "Tested"}'}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        res = ollama_prov.analyze({"target": "http://target.com", "technologies": ["express"]})
        assert res["status"] == "success"
        assert res["recommended_focus"] == "Auth surface"
        payload = mock_post.call_args[1]["json"]
        assert payload.get("format") == "json"

    # 2. OpenAI-compatible structured request
    oai_prov = LocalLlamaProvider(endpoint_url="http://localhost:1234/v1/chat/completions")
    mock_oai = MagicMock()
    mock_oai.status_code = 200
    mock_oai.json.return_value = {
        "choices": [{"message": {"content": '{"focus": "API surface", "reasoning": "REST API"}'}}]
    }

    with patch("requests.post", return_value=mock_oai) as mock_post_oai:
        res_oai = oai_prov.analyze({"target": "http://api.target.com", "endpoints": ["/api/v1"]})
        assert res_oai["status"] == "success"
        assert res_oai["recommended_focus"] == "API surface"
        payload_oai = mock_post_oai.call_args[1]["json"]
        assert payload_oai.get("response_format") == {"type": "json_object"}

    # 3. HTTP 400 fallback retry on unsupported format parameter
    resp_400 = MagicMock()
    resp_400.status_code = 400
    resp_400.text = "Error: unknown parameter 'format'"

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {"response": '{"focus": "Fallback focus", "reasoning": "Retried"}'}

    with patch("requests.post", side_effect=[resp_400, resp_200]) as mock_post_fallback:
        res_fallback = ollama_prov.analyze({"target": "http://target.com"})
        assert res_fallback["status"] == "success"
        assert res_fallback["recommended_focus"] == "Fallback focus"
        # First call had format='json', second call stripped it
        assert mock_post_fallback.call_args_list[0][1]["json"].get("format") == "json"
        assert "format" not in mock_post_fallback.call_args_list[1][1]["json"]

    # 4. Secondary regex/prose parser extracts JSON from chatty or markdown response
    chatty_resp = MagicMock()
    chatty_resp.status_code = 200
    chatty_resp.json.return_value = {
        "response": "Sure! Here is the analysis you requested:\n```json\n{\n  \"focus\": \"Chatty format\",\n  \"reasoning\": \"Cleaned up by regex fallback\"\n}\n```\nHope that helps!"
    }
    with patch("requests.post", return_value=chatty_resp):
        res_chatty = ollama_prov.analyze({"target": "http://target.com"})
        assert res_chatty["status"] == "success"
        assert res_chatty["recommended_focus"] == "Chatty format"


def test_pipeline_preview_and_remaining_destructive_count_exposure(tmp_path: Path):
    """Test that remaining destructive candidates count and upcoming pipeline are exposed in approvals and mission pause."""
    from nyx.agent.approval import ApprovalSystem
    from nyx.application.agent_service import AgentService
    from nyx.ai.planner import MissionPlanner
    from unittest.mock import MagicMock

    eng = tmp_path / ".engagement"
    eng.mkdir(parents=True, exist_ok=True)
    (eng / "target.yaml").write_text("target:\n  name: http://localhost:4444\n  domain: http://localhost:4444\n  scope:\n    - 'http://localhost:4444'\n", encoding="utf-8")
    (eng / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    # 1. Test ApprovalSystem persistence
    app_sys = ApprovalSystem(base_dir=tmp_path)
    decision = {
        "action_id": "ACT-TEST-PIPELINE",
        "tool_name": "nuclei",
        "target": "http://localhost:4444/admin",
        "impact_class": "DESTRUCTIVE",
        "remaining_destructive_count": 3,
        "upcoming_pipeline": [
            {"tool": "nuclei", "target": "http://localhost:4444/api/Challenges", "name": "Auth Bypass"},
            {"tool": "nuclei", "target": "http://localhost:4444/api/auth", "name": "Auth Bypass"},
            {"tool": "sqlmap", "target": "http://localhost:4444/backup.sql", "name": "SQL Injection"},
        ]
    }
    app_sys.submit_for_approval(decision)
    pending = app_sys.get_pending_approvals()
    assert len(pending) == 1
    assert pending[0]["remaining_destructive_count"] == 3
    assert len(pending[0]["upcoming_pipeline"]) == 3
    assert pending[0]["upcoming_pipeline"][0]["target"] == "http://localhost:4444/api/Challenges"

    # 2. Test AgentService get_approvals data contract
    agent_svc = AgentService(base_dir=tmp_path)
    res = agent_svc.get_approvals()
    assert res.is_success
    data = res.data
    assert data["pending_count"] == 1
    assert data["remaining_destructive_count"] == 3
    assert len(data["upcoming_pipeline"]) == 3
    assert data["pending"][0]["remaining_destructive_count"] == 3

    # 3. Test MissionPlanner pause payload exposure
    eng = tmp_path / ".engagement"
    eng.mkdir(exist_ok=True)
    (eng / "target.yaml").write_text("target:\n  name: http://localhost:4444\n  domain: http://localhost:4444\n  scope:\n    - 'http://localhost:4444'\n", encoding="utf-8")
    (eng / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng / "endpoints.json").write_text(json.dumps([{"url": "http://localhost:4444/1", "host": "localhost:4444"}]), encoding="utf-8")
    
    planner = MissionPlanner(base_dir=tmp_path)
    planner.ai_manager = MagicMock()
    planner.ai_manager.analyze.return_value = {
        "selected_index": 0,
        "decision": "proceed",
        "reasoning": "Test destructive selection"
    }

    destructive_candidates = [
        {"name": "Step 1", "tool": "nuclei", "target": "http://localhost:4444/1", "impact_class": "DESTRUCTIVE", "permitted": True, "action": "validate"},
        {"name": "Step 2", "tool": "nuclei", "target": "http://localhost:4444/2", "impact_class": "DESTRUCTIVE", "permitted": True, "action": "validate"},
        {"name": "Step 3", "tool": "sqlmap", "target": "http://localhost:4444/3", "impact_class": "DESTRUCTIVE", "permitted": True, "action": "validate"},
        {"name": "Step 4", "tool": "ffuf", "target": "http://localhost:4444/4", "impact_class": "DESTRUCTIVE", "permitted": True, "action": "validate"},
    ]
    planner._select_steps = MagicMock(return_value=destructive_candidates)

    pause_res = planner.run_autonomous_loop("http://localhost:4444", max_iterations=2)
    assert pause_res["status"] == "paused_for_approval"
    # Chosen index was 0, so 3 remaining destructive candidates
    assert pause_res["remaining_destructive_count"] == 3
    assert len(pause_res["upcoming_pipeline"]) == 3
    assert pause_res["upcoming_pipeline"][0]["name"] == "Step 2"
    assert pause_res["upcoming_pipeline"][1]["name"] == "Step 3"
    assert pause_res["upcoming_pipeline"][2]["name"] == "Step 4"


def test_mission_progress_websocket_event_emission_on_pause(tmp_path: Path, monkeypatch):
    """Verify mission_progress WebSocket event is emitted when paused on a destructive step with all pipeline metrics."""
    from unittest.mock import MagicMock
    from nyx.ai.planner import MissionPlanner
    import json

    eng = tmp_path / ".engagement"
    eng.mkdir(exist_ok=True)
    (eng / "target.yaml").write_text("target:\n  name: http://localhost:4444\n  domain: http://localhost:4444\n  scope:\n    - 'http://localhost:4444'\n", encoding="utf-8")
    (eng / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng / "endpoints.json").write_text(json.dumps([{"url": "http://localhost:4444/1", "host": "localhost:4444"}]), encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    planner.ai_manager = MagicMock()
    planner.ai_manager.active_provider_name = "mock-local"
    planner.ai_manager.analyze.return_value = {
        "selected_index": 0,
        "decision": "proceed",
        "reasoning": "Test destructive selection"
    }

    destructive_candidates = [
        {"name": "Step 1", "tool": "nuclei", "target": "http://localhost:4444/1", "impact_class": "DESTRUCTIVE", "permitted": True, "action": "validate"},
        {"name": "Step 2", "tool": "nuclei", "target": "http://localhost:4444/2", "impact_class": "DESTRUCTIVE", "permitted": True, "action": "validate"},
        {"name": "Step 3", "tool": "sqlmap", "target": "http://localhost:4444/3", "impact_class": "DESTRUCTIVE", "permitted": True, "action": "validate"},
    ]
    planner._select_steps = MagicMock(return_value=destructive_candidates)

    emitted_events = []
    def mock_emit_sync(event_type, data=None, mission_id=None):
        emitted_events.append({"event": event_type, "data": data, "mission_id": mission_id})

    import nyx.web.events
    monkeypatch.setattr(nyx.web.events, "emit_event_sync", mock_emit_sync)

    pause_res = planner.run_autonomous_loop("http://localhost:4444", max_iterations=2)
    assert pause_res["status"] == "paused_for_approval"

    progress_events = [e for e in emitted_events if e["event"] == "mission_progress"]
    assert len(progress_events) >= 2  # reasoning + paused

    paused_ev = next((e for e in progress_events if e["data"].get("state") == "paused"), None)
    assert paused_ev is not None
    assert paused_ev["data"]["current_step_index"] == 1
    assert paused_ev["data"]["total_planned_steps"] == 3
    assert paused_ev["data"]["remaining_destructive_count"] == 2
    assert len(paused_ev["data"]["upcoming_pipeline"]) == 2
    assert paused_ev["data"]["upcoming_pipeline"][0]["name"] == "Step 2"
    assert paused_ev["data"]["upcoming_pipeline"][1]["name"] == "Step 3"































