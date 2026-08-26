"""
Tests for NYX Phase 4 - Real Execution & Evidence Validation
Validates end-to-end mission flow, classification, deterministic validation gates,
failure distinctions, tested-vector persistence, and security boundaries.
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from nyx.application.execution_service import ExecutionService
from nyx.application.analysis_service import AnalysisService
from nyx.application.finding_service import FindingService
from nyx.application.validation_service import ValidationService
from nyx.ai.planner import MissionPlanner
from nyx.execution.engine import ExecutionEngine
from nyx.validation.rules import get_rule, VALIDATION_RULES
from nyx.core.findings import triage_finding, TRIAGE_QUESTIONS, create_finding


def test_validation_rules_expansion():
    """Verify validation rules exist and alias correctly for modern vulnerability classes."""
    assert get_rule("graphql") is not None
    assert get_rule("fintech_graphql") is not None
    assert get_rule("ssrf") is not None
    assert get_rule("cache_poison") is not None
    assert get_rule("race_condition") is not None
    assert get_rule("idor") is not None
    assert get_rule("sqli") is not None
    assert get_rule("reflected_xss") is not None


def test_classification_is_distinct_from_vulnerability_confirmation():
    """Verify classifying /graphql or /admin detects attack surface without confirming a vulnerability."""
    analysis_svc = AnalysisService()

    c_gql = analysis_svc.classify_url("https://api.example.com/graphql")
    assert c_gql["category"] == "GRAPHQL_SURFACE"
    assert "hunt-graphql" in c_gql["skills"]
    # Classification is an attack surface mapping, not a finding verdict
    assert "confirmed_vulnerability" not in c_gql

    c_auth = analysis_svc.classify_url("https://example.com/admin/login.php")
    assert c_auth["category"] == "AUTH_IDENTITY_SURFACE"
    assert "hunt-auth-bypass" in c_auth["skills"]
    assert "confirmed_vulnerability" not in c_auth


def test_deterministic_validation_confirmed_with_real_evidence(tmp_path: Path, monkeypatch):
    """Verify ValidationService confirms finding when required evidence is present."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: api.target.com\nscope:\n  - api.target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    # Create finding
    f_svc = FindingService(base_dir=tmp_path)
    res_f = f_svc.create(
        title="Cross-Tenant GraphQL IDOR in Account Query",
        endpoint="https://api.target.com/graphql",
        parameter="userId",
        vulnerability="graphql",
        description="Querying other user IDs returns their private data.",
        evidence_ids=["EV-001", "EV-002"],
    )
    fid = res_f["finding"]["finding_id"]

    # Store evidence metadata
    ev_dir = eng_dir / "evidence" / "EV-RUN-1"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "metadata.json").write_text(json.dumps([
        {"evidence_id": "EV-001", "type": "http_request", "path": "req.txt"},
        {"evidence_id": "EV-002", "type": "http_response", "path": "res.txt"},
    ]), encoding="utf-8")

    val_svc = ValidationService(base_dir=tmp_path)
    v_res = val_svc.validate_finding(fid)

    assert v_res["validation"]["status"] == "CONFIRMED"
    assert v_res["validation"]["state"] == "CONFIRMED"
    assert v_res["validation"]["confidence"] >= 80


def test_seven_question_gate_rejection_and_kill(tmp_path: Path, monkeypatch):
    """Verify 7-Question Gate rejects and marks KILL on never-submit bug classes."""
    markdown_content = """---
title: "Missing HSTS Header on Login"
severity: "Medium"
endpoint: "https://example.com/login"
---
## Summary
The server does not send Strict-Transport-Security header.

## Steps
1. curl -I https://example.com/login
2. Observe absence of HSTS.

## Impact
Theoretical man in the middle.
"""
    f_path = tmp_path / "finding_hsts.md"
    f_path.write_text(markdown_content, encoding="utf-8")

    res = triage_finding(str(f_path), base_dir=tmp_path)
    assert res["verdict"] == "KILL"
    assert res["status"] == "FAILED"
    assert "Q7" in res["failed_questions"]


def test_mission_plan_execution_records_tested_vectors(tmp_path: Path, monkeypatch):
    """Verify execute_plan updates .engagement/tested_vectors.json with accurate status."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: target.com\nscope:\n  - target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps(["https://target.com/api/v1/users"]), encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("target.com", active_permitted=False)
    exec_res = planner.execute_plan(plan, active_permitted=False)

    assert exec_res["status"] == "success"
    assert exec_res["executed_steps"] > 0

    v_file = eng_dir / "tested_vectors.json"
    assert v_file.exists()
    vectors = json.loads(v_file.read_text(encoding="utf-8"))
    assert len(vectors) > 0
    # Verified vector fields
    assert all("vector" in v and "endpoint" in v and "result" in v for v in vectors)


def test_failure_type_distinction_infrastructure_vs_negative(tmp_path: Path, monkeypatch):
    """Verify execution failure / policy block is not marked as security negative."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: target.com\nscope:\n  - target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: false\n", encoding="utf-8")

    engine = ExecutionEngine(base_dir=tmp_path)
    # Target unauthorized -> must block
    res = engine.execute("httpx", "target.com", active_permitted=True)
    assert res.status == "BLOCKED"
    assert res.authorized is False


def test_execution_time_out_of_scope_rejection(tmp_path: Path, monkeypatch):
    """Verify ExecutionEngine blocks out-of-scope targets even if passed directly."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: target.com\nscope:\n  - target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    engine = ExecutionEngine(base_dir=tmp_path)
    res = engine.execute("httpx", "evil-unauthorized.com", active_permitted=True)
    assert res.status == "BLOCKED"
    assert "OUT_OF_SCOPE" in res.scope_status or "UNAUTHORIZED" in res.scope_status


def test_finding_provenance_and_lifecycle_state_sync(tmp_path: Path, monkeypatch):
    """Verify finding provenance is tracked and state machine synchronizes on disk."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: api.bank.com\nscope:\n  - api.bank.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    f_svc = FindingService(base_dir=tmp_path)
    res_f = f_svc.create(
        title="Unauthorized Money Transfer in GraphQL Mutation",
        endpoint="https://api.bank.com/graphql",
        parameter="mutation transferFunds",
        vulnerability="graphql",
        severity="High",
        description="Transfer funds mutation executes across tenant accounts without session validation.",
        evidence_ids=["EV-GQL-1", "EV-GQL-2"],
    )
    fid = res_f["finding"]["finding_id"]

    # Initial state is HYPOTHESIS
    f_stored = f_svc.get_finding(fid)
    assert f_stored["status"] == "HYPOTHESIS"
    assert f_stored["endpoint"] == "https://api.bank.com/graphql"

    # Add evidence metadata
    ev_dir = eng_dir / "evidence" / "EV-RUN-2"
    ev_dir.mkdir(parents=True, exist_ok=True)
    (ev_dir / "metadata.json").write_text(json.dumps([
        {"evidence_id": "EV-GQL-1", "type": "http_request", "path": "req.txt"},
        {"evidence_id": "EV-GQL-2", "type": "http_response", "path": "res.txt"},
    ]), encoding="utf-8")

    val_svc = ValidationService(base_dir=tmp_path)
    v_res = val_svc.validate_finding(fid)

    assert v_res["validation"]["state"] == "CONFIRMED"
    # Verify disk synchronization in both finding.json and findings.json
    f_updated = f_svc.get_finding(fid)
    assert f_updated["status"] == "CONFIRMED"
    assert f_updated["confidence"] >= 80


def test_missing_evidence_results_in_non_confirmed_state(tmp_path: Path, monkeypatch):
    """Verify finding with missing empirical evidence is not confirmed."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: api.bank.com\nscope:\n  - api.bank.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    f_svc = FindingService(base_dir=tmp_path)
    res_f = f_svc.create(
        title="Theoretical SQL Injection in Search",
        endpoint="https://api.bank.com/search",
        parameter="q",
        vulnerability="sqli",
        description="Search parameter might be vulnerable.",
        evidence_ids=[],
    )
    fid = res_f["finding"]["finding_id"]

    val_svc = ValidationService(base_dir=tmp_path)
    v_res = val_svc.validate_finding(fid)

    # Without evidence, cannot be CONFIRMED
    assert v_res["validation"]["state"] != "CONFIRMED"
    assert v_res["validation"]["status"] != "CONFIRMED"
    assert len(v_res["validation"]["missing"]) > 0


def test_security_invariants_ai_and_knowledge_cannot_execute(tmp_path: Path, monkeypatch):
    """Verify AI plan execution must strictly pass through the Policy Engine and cannot bypass scope."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: target.com\nscope:\n  - target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    # When active_permitted is False, execution must run in dry_run mode
    plan = planner.create_plan("target.com", active_permitted=False)
    exec_res = planner.execute_plan(plan, active_permitted=False)

    assert exec_res["status"] == "success"
    for step in exec_res["step_results"]:
        tool = step["tool"]
        if tool in ("httpx", "subfinder", "katana"):
            res = step["result"]
            data = res.get("data", {}) if isinstance(res, dict) else {}
            assert data.get("dry_run") is True



