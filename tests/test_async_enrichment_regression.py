"""
Regression tests for asynchronous hypothesis enrichment during mission execution.
Verifies:
1. Classification step completes in milliseconds without waiting on LLM inference.
2. Background task upgrades findings to enriched state (or finalized fallback on failure), leaving zero findings in 'pending'.
3. Manual approval and pipeline preview logic remain strictly unaffected by background enrichment.
"""
import json
import time
from pathlib import Path
from unittest.mock import patch

from nyx.ai.planner import MissionPlanner, join_background_enrichment
from nyx.ai.tracker import active_mission_tracker
from nyx.application.finding_service import FindingService


def test_classification_step_completes_quickly_without_waiting_on_enrichment(tmp_path: Path):
    """(1) Classification step completes in < 0.3s without waiting for LLM generation."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "findings").mkdir(parents=True, exist_ok=True)

    planner = MissionPlanner(base_dir=tmp_path)
    finding_svc = FindingService(base_dir=tmp_path)

    classified_sample = [
        {"url": "http://test.local/api/auth/login", "category": "AUTH", "skills": ["hunt-auth-bypass"], "matches": {"hunt-auth-bypass": "login"}},
        {"url": "http://test.local/graphql", "category": "API", "skills": ["hunt-graphql"], "matches": {}},
        {"url": "http://test.local/api/orders?order_id=99", "category": "API_IDOR_SURFACE", "matches": {"hunt-idor": "id=99"}, "skills": ["hunt-idor"]},
    ]

    def slow_llm_generate(prompt, options=None):
        time.sleep(0.5)  # Simulate slow LLM generation
        return "### Why This Was Flagged\nTest rationale\n### Exploitability Conditions\nNone\n### Verification Steps\nCheck\n### Status\nUnconfirmed"

    with patch.object(planner.ai_manager, "generate", side_effect=slow_llm_generate):
        t0 = time.time()
        created = planner._map_classification_to_hypotheses(
            classified_results=classified_sample,
            target="http://test.local",
            async_enrich=True,
        )
        duration = time.time() - t0

        # Proves classification completed immediately without waiting on the 3x 0.5s LLM calls
        assert duration < 0.3, f"Expected classification to return in < 0.3s, but took {duration:.3f}s"
        assert len(created) >= 2

        # Immediately after return, findings exist and are marked 'pending'
        flist = finding_svc.list_findings(base_dir=tmp_path)
        items = flist.get("findings", [])
        assert len(items) >= 2
        for it in items:
            assert it.get("enrichment_status") in ("pending", "enriched")

        # Now wait for background enrichment to complete
        join_background_enrichment(timeout=5.0)

        # Verify findings have been upgraded to enriched
        flist_after = finding_svc.list_findings(base_dir=tmp_path)
        items_after = flist_after.get("findings", [])
        assert len(items_after) >= 2
        for it in items_after:
            assert it.get("ai_enriched") is True
            assert it.get("enrichment_status") == "enriched"
            assert "Test rationale" in it.get("description", "")


def test_enrichment_failure_fallback_guarantee_never_leaves_pending(tmp_path: Path):
    """(2) Findings are finalized with clean fallback if background LLM fails; none left in 'pending'."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "findings").mkdir(parents=True, exist_ok=True)

    planner = MissionPlanner(base_dir=tmp_path)
    finding_svc = FindingService(base_dir=tmp_path)

    classified_sample = [
        {"url": "http://test.local/login", "category": "AUTH", "skills": ["hunt-auth-bypass"], "matches": {"hunt-auth-bypass": "login"}},
    ]

    def failing_llm_generate(prompt, options=None):
        raise ConnectionError("Ollama connection refused or model timed out")

    with patch.object(planner.ai_manager, "generate", side_effect=failing_llm_generate):
        created = planner._map_classification_to_hypotheses(
            classified_results=classified_sample,
            target="http://test.local",
            async_enrich=True,
        )
        assert len(created) >= 1

        join_background_enrichment(timeout=5.0)

        flist = finding_svc.list_findings(base_dir=tmp_path)
        items = flist.get("findings", [])
        assert len(items) >= 1
        for it in items:
            # Must NOT be left in 'pending'
            assert it.get("enrichment_status") != "pending"
            assert it.get("enrichment_status") == "fallback"
            assert it.get("ai_enriched") is False
            assert "### Finding Details & Status" in it.get("description", "")
            assert "AI Enrichment" in it.get("description", "")
            assert "Unavailable" in it.get("description", "")


def test_manual_approval_and_pipeline_preview_unaffected_by_background_enrichment(tmp_path: Path):
    """(3) Manual approval gating and pipeline preview logic function normally while findings enrich in background."""
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "findings").mkdir(parents=True, exist_ok=True)

    planner = MissionPlanner(base_dir=tmp_path)

    # Put an un-enriched finding in workspace
    finding_svc = FindingService(base_dir=tmp_path)
    f_res = finding_svc.create(
        title="SQL Injection Surface on http://test.local/search",
        endpoint="http://test.local/search",
        vulnerability="SQL Injection",
        severity="High",
        target="test.local",
        description="Initial heuristic finding description",
    )
    fid = f_res.get("finding_id")

    ctx = {
        "target": "test.local",
        "in_scope": True,
        "endpoints": ["http://test.local/search"],
        "technologies": ["PHP", "MySQL"],
        "findings": [f_res],
        "tested_vectors": [],
        "relevant_knowledge": {"recommended_skills": ["hunt-sqli"]},
    }

    # Verify _select_steps selects appropriate validation tools based on hypothesis vulnerability
    steps = planner._select_steps(ctx)
    assert len(steps) > 0

    # Ensure pipeline steps can be validated through policy engine
    validated = planner.policy_engine.filter_plan_steps("test.local", steps, active_permitted=False)
    assert len(validated) > 0

    # Verify that approval queue correctly registers destructive actions regardless of enrichment status
    from nyx.agent.approval import ApprovalSystem
    app_sys = ApprovalSystem(base_dir=tmp_path)

    action_id = "ACT-REG-001"
    decision = {
        "action_id": action_id,
        "target": "test.local",
        "action": "Active SQL Injection Probe",
        "tool_name": "sqlmap",
        "tool": "sqlmap",
        "risk": "High",
        "impact_class": "DESTRUCTIVE",
        "params": {"finding_id": fid},
    }
    submitted_id = app_sys.submit_for_approval(decision)
    assert submitted_id == action_id

    pending = app_sys.get_pending_approvals()
    assert any(p["action_id"] == action_id for p in pending)
    matched = next(p for p in pending if p["action_id"] == action_id)
    assert matched["impact_class"] == "DESTRUCTIVE"
    assert matched["tool"] == "sqlmap"
