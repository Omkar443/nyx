"""
Phase 14.0 — Claude Agent Integration Layer & Intelligent Orchestration Verification Suite
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nyx.ai.base import AIProvider
from nyx.ai.providers.gemini import GeminiProvider
from nyx.ai.providers.claude import ClaudeProvider
from nyx.ai.providers.openai import OpenAIProvider
from nyx.ai.providers.local import LocalLLMProvider
from nyx.ai.manager import AIManager
from nyx.ai.context import ContextEngine
from nyx.ai.planner import MissionPlanner
from nyx.ai.memory import AIMemory
from nyx.security.ai_policy import AIPolicyEngine
from nyx.application.ai_service import AIService
from nyx.application.base import ServiceResult
from nyx.api.agent import (
    get_target_context,
    list_skills,
    run_recon,
    execute_tool,
    validate_finding,
    generate_report,
    plan_mission,
)
from nyx.mcp import (
    list_mcp_tools,
    list_mcp_resources,
    RECON_TARGET_SCHEMA,
    EXECUTE_TOOL_SCHEMA,
    CLASSIFY_URL_SCHEMA,
    TRIAGE_FINDING_SCHEMA,
    GENERATE_REPORT_SCHEMA,
)


def run_phase140_tests() -> int:
    print("=" * 60)
    print(" PHASE 14.0 Claude AGENT INTEGRATION & ORCHESTRATION TESTS")
    print("=" * 60)

    test_dir = REPO_ROOT / "test-phase140-workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    cwd_orig = Path.cwd()
    os.chdir(test_dir)

    passed = 0
    total = 0

    try:
        # Test 1: Zero reverse imports (nyx -> nyx/nyx_cli.cli)
        total += 1
        nyx_dir = REPO_ROOT / "nyx"
        illegal_imports = []
        for py_file in nyx_dir.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8")
            for line in text.splitlines():
                line_str = line.strip()
                if line_str.startswith("import nyx_cli") or line_str.startswith("from nyx_cli"):
                    illegal_imports.append((str(py_file), line_str))

        if len(illegal_imports) == 0:
            print("[1_zero_nyx_imports] PASS - 0 nyx/nyx_cli.cli imports in nyx/")
            passed += 1
        else:
            print(f"[1_zero_nyx_imports] FAIL - Found illegal imports: {illegal_imports}")

        # Test 2: Provider Abstraction & Switching
        total += 1
        mgr = AIManager(default_provider="gemini")
        prov_list = mgr.list_providers()
        gemini_gen = mgr.generate("Generate mission plan")

        mgr.set_active_provider("claude")
        claude_gen = mgr.generate("Generate mission plan")

        mgr.set_active_provider("local")
        local_gen = mgr.generate("Generate mission plan")

        if (
            len(prov_list) == 4
            and "Gemini" in gemini_gen or "Mission" in gemini_gen
            and "Claude" in claude_gen or "Mission" in claude_gen
            and "Local" in local_gen or "Mission" in local_gen
        ):
            print("[2_provider_abstraction] PASS - AI Provider abstraction & dynamic switching operating cleanly")
            passed += 1
        else:
            print(f"[2_provider_abstraction] FAIL - Provider test results: list={len(prov_list)}")

        # Test 3: Context Engine Target Context Generation
        total += 1
        from nyx.core.engagement import init_engagement
        init_engagement("example.com")

        ctx_engine = ContextEngine(base_dir=test_dir)
        ctx = ctx_engine.get_target_context("example.com")

        if (
            ctx.get("target") == "example.com"
            and ctx.get("in_scope") is True
            and "phase" in ctx
            and isinstance(ctx.get("technologies"), list)
            and isinstance(ctx.get("skills"), list)
        ):
            print("[3_context_engine] PASS - ContextEngine generated structured security context")
            passed += 1
        else:
            print(f"[3_context_engine] FAIL - Context structure mismatch: {ctx}")

        # Test 4: Mission Reasoner & Planner Output
        total += 1
        planner = MissionPlanner(base_dir=test_dir)
        plan = planner.create_plan("example.com", provider_name="gemini")

        if (
            plan.get("target") == "example.com"
            and plan.get("provider") == "gemini"
            and len(plan.get("steps", [])) == 4
            and "recommended_focus" in plan
        ):
            print("[4_mission_planner] PASS - MissionPlanner generated structured policy-checked plan")
            passed += 1
        else:
            print(f"[4_mission_planner] FAIL - Plan output: {plan}")

        # Test 5: AI Policy Security Enforcement
        total += 1
        pol_engine = AIPolicyEngine(base_dir=test_dir)

        # Authorized & in-scope passive step
        ok_passive, msg_passive = pol_engine.check_action_permitted("passive_recon", "example.com")

        # Out-of-scope step
        ok_scope, msg_scope = pol_engine.check_action_permitted("passive_recon", "unrelated-domain.org")

        if ok_passive is True and ok_scope is False and "[SCOPE BLOCKED]" in msg_scope:
            print("[5_policy_enforcement] PASS - AIPolicyEngine correctly enforced scope & authorization gates")
            passed += 1
        else:
            print(f"[5_policy_enforcement] FAIL - Passive: {ok_passive}, Scope: {ok_scope} ({msg_scope})")

        # Test 6: AI Memory Failure Tracking
        total += 1
        memory = AIMemory(base_dir=test_dir)
        memory.clear()
        memory.record_failed_approach("example.com", "sqli_login", "WAF parameter sanitization")

        failed_vecs = memory.get_failed_approaches("example.com")

        if len(failed_vecs) == 1 and failed_vecs[0].get("vector") == "sqli_login":
            print("[6_ai_memory] PASS - AIMemory correctly recorded and retrieved failed attack approach")
            passed += 1
        else:
            print(f"[6_ai_memory] FAIL - Memory records: {failed_vecs}")

        # Test 7: MCP Preparation Layer
        total += 1
        mcp_tools = list_mcp_tools()
        mcp_resources = list_mcp_resources()

        if (
            len(mcp_tools) >= 5
            and len(mcp_resources) >= 4
            and RECON_TARGET_SCHEMA.get("type") == "object"
            and EXECUTE_TOOL_SCHEMA.get("type") == "object"
        ):
            print("[7_mcp_preparation] PASS - MCP-ready tools, resources, and schemas validated")
            passed += 1
        else:
            print(f"[7_mcp_preparation] FAIL - MCP tools: {len(mcp_tools)}, resources: {len(mcp_resources)}")

        # Test 8: Agent API Programmatic Interfaces
        total += 1
        agent_ctx = get_target_context("example.com")
        agent_skills = list_skills()
        agent_plan = plan_mission("example.com", provider_name="claude")

        if (
            agent_ctx.get("target") == "example.com"
            and agent_skills.get("success") is True
            and agent_plan.get("provider") == "claude"
        ):
            print("[8_agent_api] PASS - nyx.api.agent functions executed cleanly")
            passed += 1
        else:
            print(f"[8_agent_api] FAIL - Agent API outputs invalid")

        # Test 9: Application AIService Facade
        total += 1
        ai_svc = AIService(base_dir=test_dir)
        svc_provs = ai_svc.list_providers()
        svc_ctx = ai_svc.get_context("example.com")
        svc_stat = ai_svc.get_status()

        if (
            svc_provs.is_success
            and svc_ctx.is_success
            and svc_stat.is_success
            and svc_stat.data.get("active_provider") == "gemini"
        ):
            print("[9_ai_service_facade] PASS - AIService returned structured ServiceResult responses")
            passed += 1
        else:
            print(f"[9_ai_service_facade] FAIL - Service results: provs={svc_provs}, ctx={svc_ctx}, stat={svc_stat}")

        # Test 10: CLI Compatibility Adapter nyx ai execution
        total += 1
        import subprocess

        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT)

        cmd_provs = [sys.executable, "-m", "nyx_cli.cli", "ai", "providers"]
        p_provs = subprocess.run(cmd_provs, cwd=test_dir, env=env, capture_output=True, text=True)

        cmd_plan = [sys.executable, "-m", "nyx_cli.cli", "ai", "plan", "example.com"]
        p_plan = subprocess.run(cmd_plan, cwd=test_dir, env=env, capture_output=True, text=True)

        cmd_stat = [sys.executable, "-m", "nyx_cli.cli", "ai", "status"]
        p_stat = subprocess.run(cmd_stat, cwd=test_dir, env=env, capture_output=True, text=True)

        if (
            p_provs.returncode == 0
            and p_plan.returncode == 0
            and p_stat.returncode == 0
            and "NYX Registered AI Providers" in p_provs.stdout
            and "Recommended Mission" in p_plan.stdout
        ):
            print("[10_cli_ai_adapter] PASS - CLI nyx ai commands parsed & executed cleanly")
            passed += 1
        else:
            print(f"[10_cli_ai_adapter] FAIL - CLI exit codes: provs={p_provs.returncode}, plan={p_plan.returncode}, stat={p_stat.returncode}. Out: {p_plan.stdout}")

    finally:
        os.chdir(cwd_orig)
        if test_dir.exists():
            try:
                shutil.rmtree(test_dir)
            except Exception:
                pass

    print("=" * 60)
    print(f" TOTAL VERIFICATIONS PASSED: {passed} / {total}")
    if passed == total:
        print(" OVERALL PHASE 14.0 SUITE RESULT: PASS")
        print("=" * 60)
        return 0
    else:
        print(" OVERALL PHASE 14.0 SUITE RESULT: FAIL")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(run_phase140_tests())
