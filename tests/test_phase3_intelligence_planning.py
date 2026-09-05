"""
Unit and regression test suite for NYX Phase 3:
Knowledge-Aware Intelligence, Provider Fail-Safes, Tested-Vector Memory, and Deterministic Planning.
"""
from __future__ import annotations

import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from nyx.core.knowledge import search_knowledge, retrieve_context_knowledge
from nyx.ai.context import ContextEngine
from nyx.ai.manager import AIManager
from nyx.ai.planner import MissionPlanner
from nyx.security.authorization import is_hostname_in_scope


def test_context_aware_knowledge_retrieval_multi_criteria():
    """Verify structured retrieval with technology, attack surface, and keywords."""
    res = search_knowledge(technology=["Next.js"], attack_surface="api", keyword=["ssr", "image"])
    assert len(res["matched_technologies"]) >= 1
    assert any("next" in str(t).lower() for t in res["matched_technologies"])
    assert "hunt-nextjs" in res["matched_skills"]


def test_retrieve_context_knowledge_auto_detection():
    """Verify that retrieve_context_knowledge automatically extracts features from context."""
    context = {
        "target": "payment.target.com",
        "phase": "ANALYSIS",
        "technologies": ["GraphQL", "React"],
        "endpoints": [
            "https://payment.target.com/payment/graphql?mutation=transferFunds",
            "https://payment.target.com/auth/login",
        ],
        "findings": [{"title": "Potential IDOR in wallet transfer", "vulnerability": "IDOR"}],
    }
    retrieved = retrieve_context_knowledge(context)
    assert "GraphQL" in retrieved["matched_technologies"]
    assert "hunt-fintech-graphql" in retrieved["recommended_skills"] or "hunt-graphql" in retrieved["recommended_skills"]
    assert "api" in retrieved["attack_surfaces"]
    assert "authentication" in retrieved["attack_surfaces"]


def test_context_engine_loads_tested_vectors_and_knowledge(tmp_path: Path):
    """Verify ContextEngine loads tested_vectors.json and enriches context with relevant_knowledge."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: app.corp.internal\nscope:\n  - app.corp.internal\n", encoding="utf-8")
    (eng_dir / "technologies.json").write_text(json.dumps(["Laravel"]), encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps(["https://app.corp.internal/api/v1/user"]), encoding="utf-8")
    (eng_dir / "tested_vectors.json").write_text(
        json.dumps([{"vector": "auth_surface_analysis", "result": "tested_negative", "target": "app.corp.internal"}]),
        encoding="utf-8",
    )

    ce = ContextEngine(base_dir=tmp_path)
    ctx = ce.get_target_context("app.corp.internal")

    assert ctx["in_scope"] is True
    assert len(ctx["tested_vectors"]) == 1
    assert ctx["tested_vectors"][0]["vector"] == "auth_surface_analysis"
    assert "relevant_knowledge" in ctx
    assert "Laravel" in ctx["relevant_knowledge"]["matched_technologies"]


def test_ai_manager_fail_safe_on_error_or_malformed():
    """Verify that AIManager.analyze returns a structured fail-safe when a provider fails."""
    mgr = AIManager()
    mock_provider = MagicMock()
    mock_provider.provider_name = "mock_cloud"
    mock_provider.analyze.side_effect = RuntimeError("API Timeout / Network error")

    mgr._instances["mock_cloud"] = mock_provider
    res = mgr.analyze({"target": "target.com"}, provider_name="mock_cloud")

    assert res["provider"] == "mock_cloud"
    assert "AI analysis unavailable" in res["recommended_focus"]
    assert "API Timeout" in res["analysis"]


def test_deterministic_planner_no_endpoints(tmp_path: Path):
    """Verify planner creates standard 3-step discovery plan when endpoints are empty."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: target.com\nscope:\n  - target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text("[]", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("target.com")

    assert plan.get("status") != "error"
    steps = plan["steps"]
    assert len(steps) == 4
    assert steps[0]["reason"] == "INITIAL_HOST_DISCOVERY"
    assert steps[1]["reason"] == "ENDPOINT_HARVESTING_REQUIRED"
    assert steps[2]["reason"] == "SURFACE_MAPPING_AND_SKILL_ROUTING"
    assert steps[3]["reason"] == "HYPOTHESIS_VALIDATION_REQUIRED"


def test_deterministic_planner_fintech_graphql_detection(tmp_path: Path):
    """Verify planner selects financial GraphQL step when payment mutation endpoints exist."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: api.bank.com\nscope:\n  - api.bank.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(
        json.dumps(["https://api.bank.com/payment/graphql?mutation=transferFunds"]),
        encoding="utf-8",
    )

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("api.bank.com")

    assert plan.get("status") != "error"
    steps = plan["steps"]
    assert len(steps) >= 1
    reasons = [s["reason"] for s in steps]
    assert "FINANCIAL_GRAPHQL_MUTATION_DETECTED" in reasons
    step = next(s for s in steps if s["reason"] == "FINANCIAL_GRAPHQL_MUTATION_DETECTED")
    assert "hunt-fintech-graphql" in step["knowledge_refs"]


def test_deterministic_planner_auth_surface_detection(tmp_path: Path):
    """Verify planner selects authentication surface analysis when login/oauth endpoints exist."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: sso.portal.com\nscope:\n  - sso.portal.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(
        json.dumps(["https://sso.portal.com/auth/login", "https://sso.portal.com/oauth/callback"]),
        encoding="utf-8",
    )

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("sso.portal.com")

    assert plan.get("status") != "error"
    reasons = [s["reason"] for s in plan["steps"]]
    assert "AUTH_SURFACE_DETECTED" in reasons


def test_deterministic_planner_tested_vector_suppression(tmp_path: Path):
    """Verify that already-tested vectors (tested_negative) are suppressed from the plan."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: auth.portal.com\nscope:\n  - auth.portal.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(
        json.dumps(["https://auth.portal.com/auth/login"]),
        encoding="utf-8",
    )
    # Record that auth surface analysis was already tested negative
    (eng_dir / "tested_vectors.json").write_text(
        json.dumps([{"vector": "auth_surface_analysis", "result": "tested_negative", "target": "auth.portal.com"}]),
        encoding="utf-8",
    )

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("auth.portal.com")

    assert plan.get("status") != "error"
    reasons = [s["reason"] for s in plan["steps"]]
    # auth_surface_analysis is suppressed; falls back to general surface mapping
    assert "AUTH_SURFACE_DETECTED" not in reasons
    assert "SURFACE_MAPPING_AND_SKILL_ROUTING" in reasons


def test_deterministic_planner_hypothesis_triage_inclusion(tmp_path: Path):
    """Verify that pending HYPOTHESIS findings trigger Controlled Vulnerability Triage."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: app.target.com\nscope:\n  - app.target.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")
    (eng_dir / "endpoints.json").write_text(json.dumps(["https://app.target.com/home"]), encoding="utf-8")
    (eng_dir / "findings.json").write_text(
        json.dumps([{"finding_id": "FH-2026-001", "state": "HYPOTHESIS", "title": "Suspected IDOR", "target": "app.target.com", "endpoint": "https://app.target.com/home"}]),
        encoding="utf-8",
    )

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("app.target.com")

    assert plan.get("status") != "error"
    reasons = [s["reason"] for s in plan["steps"]]
    assert "HYPOTHESIS_VALIDATION_REQUIRED" in reasons
    triage_step = next(s for s in plan["steps"] if s["reason"] == "HYPOTHESIS_VALIDATION_REQUIRED")
    assert triage_step["evidence"] == ["FH-2026-001"]


def test_planner_out_of_scope_rejection(tmp_path: Path):
    """Verify fail-closed rejection for out-of-scope targets."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "target.yaml").write_text("target: inscope.com\nscope:\n  - inscope.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    planner = MissionPlanner(base_dir=tmp_path)
    plan = planner.create_plan("unauthorized-victim.com")
    assert plan["status"] == "error"
    assert "does not match the active engagement's scope" in plan["error"]
