#!/usr/bin/env python3
"""
Phase 6.0 — NYX Intelligence Layer Automated Test Suite
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import os

def run_cli(args, cwd):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    cmd = [sys.executable, "-m", "nyx_cli.cli"] + args
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr

def run_phase60_tests():
    test_dir = REPO_ROOT / "test-phase60-workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 6.0 NYX INTELLIGENCE LAYER TESTS")
    print("==================================================")

    # 1. NYX Core Imports
    try:
        import nyx.core.recon
        import nyx.core.engagement
        import nyx.core.findings
        import nyx.core.evidence
        import nyx.core.analysis
        results["1_nyx_core_imports"] = True
    except Exception as e:
        print(f"Core import failed: {e}")
        results["1_nyx_core_imports"] = False

    # 2. NYX API Imports
    try:
        import nyx.api.mission
        import nyx.api.tools
        results["2_nyx_api_imports"] = True
    except Exception as e:
        print(f"API import failed: {e}")
        results["2_nyx_api_imports"] = False

    # 3. .nyx Configuration Files Exist
    nyx_dir = REPO_ROOT / ".nyx"
    t_file = nyx_dir / "tools.yaml"
    w_file = nyx_dir / "workflows.yaml"
    p_file = nyx_dir / "policies.yaml"
    results["3_nyx_config_files_exist"] = (t_file.exists() and w_file.exists() and p_file.exists())

    # 4. Tool Registry Loads
    from nyx.api.tools import load_tools_registry, load_workflows, load_policies
    tools_data = load_tools_registry()
    results["4_tool_registry_loads"] = isinstance(tools_data, dict) and "tools" in tools_data and "recon" in tools_data.get("tools", {})

    # 5. Workflow Registry Loads
    wf_data = load_workflows()
    results["5_workflow_registry_loads"] = isinstance(wf_data, dict) and "workflows" in wf_data and "research_workflow" in wf_data.get("workflows", {})

    # 6. Mission Initialization via CLI
    rc_m_init, out_m_init, _ = run_cli(["mission", "init", "missiontest.local", "--reset"], cwd=test_dir)
    results["6_mission_init_works"] = (rc_m_init == 0 and (test_dir / ".engagement" / "target.yaml").exists())

    # 7. Mission Status via CLI
    rc_m_stat, out_m_stat, _ = run_cli(["mission", "status"], cwd=test_dir)
    results["7_mission_status_works"] = (rc_m_stat == 0 and "DISCOVERY" in out_m_stat)

    # 8. Existing CLI nyx --help & nyx --help
    rc_nyx_h, out_nyx_h, _ = run_cli(["--help"], cwd=test_dir)
    results["8_nyx_help_works"] = (rc_nyx_h == 0 and "nyx" in out_nyx_h)

    cmd_nyx = [sys.executable, "-c", "import sys; sys.argv=['nyx', '--help']; from nyx_cli.cli import main; main()"]
    env_nyx = os.environ.copy()
    env_nyx["PYTHONPATH"] = str(REPO_ROOT)
    p_nyx = subprocess.run(cmd_nyx, cwd=test_dir, capture_output=True, text=True, env=env_nyx)
    results["9_nyx_help_works"] = (p_nyx.returncode == 0 and ("nyx" in p_nyx.stdout or "nyx" in p_nyx.stdout))

    # 10. Mission CLI subcommand works
    results["10_mission_cli_works"] = (rc_m_stat == 0 and "DISCOVERY" in out_m_stat)

    # 11. Decision Context Engine
    from nyx.core.analysis import get_decision_context
    ctx = get_decision_context("https://target.com/api/v1/login.aspx", tech_stack=["ASP.NET"])
    results["11_decision_context_engine"] = (
        isinstance(ctx, dict) and
        ctx.get("surface") in ("authentication", "api_endpoint") and
        "hunt-aspnet" in ctx.get("recommended_skills", [])
    )

    print("\n==================================================")
    passed_cnt = 0
    for k, v in results.items():
        status = "PASS" if v else "FAIL"
        if v:
            passed_cnt += 1
        print(f"[{k}] {status}")
    print("==================================================")
    print(f" TOTAL VERIFICATIONS PASSED: {passed_cnt} / {len(results)}")
    print(f" OVERALL PHASE 6.0 SUITE RESULT: {'PASS' if passed_cnt == len(results) else 'FAIL'}")
    print("==================================================")

    if test_dir.exists():
        shutil.rmtree(test_dir)
    eng_test = Path.cwd() / ".engagement"
    if eng_test.exists():
        shutil.rmtree(eng_test)

    return 0 if passed_cnt == len(results) else 1

if __name__ == "__main__":
    sys.exit(run_phase60_tests())
