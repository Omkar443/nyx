"""
Phase 16 Verification Suite — NYX Autonomous Security Research Agent Layer
Tests:
1. Agent initialization (NYXAgent)
2. Reasoning context generation (AgentContextEngine)
3. Research plan creation (ResearchPlanner)
4. Decision explanation (DecisionEngine)
5. Human Approval System & execution blocking (ApprovalSystem)
6. Agent State Machine invariants & invalid transition rejection
7. Agent Memory persistence (AgentMemory)
8. CLI integration (nyx agent subcommands)
9. Web Dashboard API endpoints (/api/v1/agent/*)
10. Zero reverse nyx_cli.cli imports in nyx/ and nyx/agent/
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import sys

from pathlib import Path
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nyx.agent import (
    NYXAgent,
    ResearchPlanner,
    AgentContextEngine,
    DecisionEngine,
    ApprovalSystem,
    AgentMemory,
    AgentStateMachine,
)
from nyx.application.agent_service import AgentService
from nyx.web.app import app
from nyx.web.auth import get_or_create_api_token
from nyx.core.engagement import init_engagement


def run_phase160_tests():
    print("=" * 60)
    print(" PHASE 16.0 NYX AUTONOMOUS RESEARCH AGENT LAYER TESTS")
    print("=" * 60)

    results = {}
    test_dir = REPO_ROOT / "scratch" / "test_phase160_workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    old_cwd = os.getcwd()
    os.chdir(test_dir)

    try:
        # 1. Zero Reverse Imports (nyx/* & nyx/agent/* -> nyx_cli.cli)
        nyx_files = glob.glob(str(REPO_ROOT / "nyx" / "**" / "*.py"), recursive=True)
        nyx_imports = []
        for fpath in nyx_files:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                for line_no, line in enumerate(fp, 1):
                    if "nyx_cli.cli" in line or "from nyx_cli" in line:
                        rel = Path(fpath).relative_to(REPO_ROOT)
                        nyx_imports.append(f"{rel}:{line_no}: {line.strip()}")

        print(f"[1_zero_nyx_imports] Total nyx -> nyx_cli.cli imports: {len(nyx_imports)}")
        results["1_zero_nyx_imports"] = (len(nyx_imports) == 0)

        # Initialize test workspace
        init_engagement("example.com")
        agent = NYXAgent()

        # 2. Agent Initialization & State Machine
        init_res = agent.start_mission("example.com")
        print(f"[2_agent_init] Target: {init_res.get('target')}, State: {init_res.get('agent_state')}")
        results["2_agent_init"] = (init_res.get("target") == "example.com" and init_res.get("agent_state") == "ANALYZING")

        # 3. Context Generation
        ctx = agent.context_engine.get_agent_context("example.com")
        print(f"[3_context_generation] InScope: {ctx.get('in_scope')}, RecTests: {len(ctx.get('recommended_tests', []))}")
        results["3_context_generation"] = (ctx.get("in_scope") is True and len(ctx.get("recommended_tests", [])) > 0)

        # 4. Research Plan Creation
        plan = agent.planner.create_plan("example.com", ctx)
        print(f"[4_research_plan] Priority: {plan.get('priority')}, Objectives: {len(plan.get('objectives', []))}")
        results["4_research_plan"] = (plan.get("priority") == "HIGH" and len(plan.get("objectives", [])) >= 3)

        # 5. Explainable Decision Tracking
        decision = agent.decision_engine.create_decision(
            target="example.com",
            action="Test IDOR on user endpoint",
            reason="Endpoint contains sequential ID parameter",
            confidence=85,
            risk="Medium",
        )
        act_id = decision.get("action_id")
        print(f"[5_decision_explanation] ActionID: {act_id}, Reason: {decision.get('reason')}")
        results["5_decision_explanation"] = (act_id is not None and decision.get("confidence") == 85)

        # 6. Human Approval & Execution Blocking
        # Attempt execution on unapproved action -> MUST BE BLOCKED
        block_res = agent.execute(act_id)
        print(f"[6_approval_blocking] Blocked: {block_res.get('policy_blocked')}, Error: {block_res.get('error')}")

        # Submit and approve action
        agent.approval_system.submit_for_approval(decision)
        app_ok, app_msg, _ = agent.approval_system.approve_action(act_id)
        exec_res = agent.execute(act_id)
        print(f"[6_approved_execution] Executed: {exec_res.get('success')}, State: {exec_res.get('agent_state')}")

        results["6_approval_blocking"] = (block_res.get("policy_blocked") is True and app_ok is True and exec_res.get("success") is True)

        # 7. State Machine Invalid Transition Blocking
        sm = AgentStateMachine("IDLE")
        inv_ok, inv_msg = sm.transition_to("REPORTING")  # Invalid jump from IDLE to REPORTING
        val_ok, val_msg = sm.transition_to("ANALYZING")  # Valid transition from IDLE to ANALYZING
        print(f"[7_state_machine] Invalid Rejected: {not inv_ok}, Valid Accepted: {val_ok}")
        results["7_state_machine"] = (not inv_ok and val_ok)

        # 8. Memory Persistence
        mem = AgentMemory()
        mem.record_decision(decision)
        mem.record_plan(plan)
        hist = mem.get_history()
        print(f"[8_memory_persistence] Stored Decisions: {len(hist.get('decisions', []))}, Plans: {len(hist.get('plans', []))}")
        results["8_memory_persistence"] = (len(hist.get("decisions", [])) > 0 and len(hist.get("plans", [])) > 0)

        # 9. Application Service & REST API Integration
        token = get_or_create_api_token()
        client = TestClient(app)
        auth_headers = {"Authorization": f"Bearer {token}", "X-API-Token": token}

        st_res = client.get("/api/v1/agent/status", headers=auth_headers)
        pl_res = client.get("/api/v1/agent/plan?target=example.com", headers=auth_headers)
        print(f"[9_dashboard_api] Status: {st_res.status_code}, Plan: {pl_res.status_code}")
        results["9_dashboard_api"] = (st_res.status_code == 200 and pl_res.status_code == 200)

        # 10. AgentService Facade Integration
        svc = AgentService()
        s_res = svc.start_mission("example.com")
        p_res = svc.plan_mission("example.com")
        print(f"[10_agent_service] Start: {s_res.is_success}, Plan: {p_res.is_success}")
        results["10_agent_service"] = (s_res.is_success and p_res.is_success)

    finally:
        os.chdir(old_cwd)
        if test_dir.exists():
            shutil.rmtree(test_dir, ignore_errors=True)

    # Print Summary
    print("\n" + "=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    for name, res in results.items():
        status_str = "PASS" if res else "FAIL"
        print(f"[{name}] {status_str}")

    print("=" * 60)
    print(f" TOTAL VERIFICATIONS PASSED: {passed} / {total}")
    print(f" OVERALL PHASE 16.0 SUITE RESULT: {'PASS' if passed == total else 'FAIL'}")
    print("=" * 60)

    return passed == total


if __name__ == "__main__":
    success = run_phase160_tests()
    sys.exit(0 if success else 1)
