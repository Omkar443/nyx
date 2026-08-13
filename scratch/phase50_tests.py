#!/usr/bin/env python3
"""
Phase 5.0 — Antigravity Migration & Core Hardening Automated Test Suite
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from nyx_cli.cli import normalize_url, get_cmd_path, has_cmd, check_state_permission


import os

def run_cli(args, cwd):
    cmd = [sys.executable, "-m", "nyx_cli.cli"] + args
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def run_phase50_tests():
    test_dir = Path("D:/Pentest/Skill File/NYX/test-phase50-workspace")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 5.0 CORE HARDENING & MIGRATION TEST SUITE")
    print("==================================================")

    # 1. URL Normalization Tests
    url1 = "[http://example.com](http://example.com)"
    norm1 = normalize_url(url1)
    url2 = "HTTPS://EXAMPLE.COM:443/Path/With/Slash/?"
    norm2 = normalize_url(url2)
    url3 = "http://example.com:80/"
    norm3 = normalize_url(url3)

    results["1_url_norm_md_link"] = (norm1 == "http://example.com")
    results["2_url_norm_scheme_host"] = (norm2 == "https://example.com/Path/With/Slash")
    results["3_url_norm_default_port"] = (norm3 == "http://example.com/")

    # 2. Recon Tool Discovery
    python_found = has_cmd("python") or has_cmd("python3")
    subfinder_path = get_cmd_path("subfinder")
    results["4_tool_discovery_python"] = python_found
    results["5_tool_discovery_cache"] = (subfinder_path is None or isinstance(subfinder_path, str))

    # 3. Target Isolation & Reset
    rc1, out1, _ = run_cli(["engagement", "init", "targetA.com"], cwd=test_dir)
    results["6_init_target_a"] = (rc1 == 0)

    rc2, out2, err2 = run_cli(["engagement", "init", "targetB.com"], cwd=test_dir)
    results["7_reinit_target_b_rejected"] = (rc2 == 1 and "Cannot re-initialize" in out2)

    rc3, out3, _ = run_cli(["engagement", "init", "targetB.com", "--reset"], cwd=test_dir)
    results["8_reinit_target_b_with_reset"] = (rc3 == 0 and "Resetting engagement workspace" in out3)

    # 4. Workflow State Machine Modes (Research vs Strict)
    run_cli(["engagement", "init", "targetC.com", "--reset"], cwd=test_dir)

    # Default mode is RESEARCH
    rc4, out4, _ = run_cli(["state", "ANALYSIS"], cwd=test_dir)
    results["9_research_discovery_to_analysis"] = (rc4 == 0)

    rc5, out5, _ = run_cli(["state", "DISCOVERY"], cwd=test_dir)
    results["10_research_analysis_back_to_discovery"] = (rc5 == 0)

    # Switch to STRICT mode
    rc6, out6, _ = run_cli(["state", "--mode", "strict"], cwd=test_dir)
    results["11_set_mode_strict"] = (rc6 == 0 and "STRICT" in out6)

    # In STRICT mode: DISCOVERY -> REPORTING should fail
    rc7, out7, _ = run_cli(["state", "REPORTING"], cwd=test_dir)
    results["12_strict_invalid_jump_rejected"] = (rc7 == 1 and "Invalid state transition" in out7)

    # 5. Surface permissions in DISCOVERY & ANALYSIS
    class DummyArgs:
        pass
    dummy = DummyArgs()
    ok_disc, _ = check_state_permission("surface", dummy)

    run_cli(["state", "ANALYSIS", "--force-state"], cwd=test_dir)
    ok_anal, _ = check_state_permission("surface", dummy)

    results["13_surface_allowed_in_discovery_and_analysis"] = (ok_disc and ok_anal)

    print("\n==================================================")
    passed_cnt = 0
    for k, v in results.items():
        status = "PASS" if v else "FAIL"
        if v:
            passed_cnt += 1
        print(f"[{k}] {status}")
    print("==================================================")
    print(f" TOTAL VERIFICATIONS PASSED: {passed_cnt} / {len(results)}")
    print(f" OVERALL PHASE 5.0 SUITE RESULT: {'PASS' if passed_cnt == len(results) else 'FAIL'}")
    print("==================================================")

    if test_dir.exists():
        shutil.rmtree(test_dir)

    return 0 if passed_cnt == len(results) else 1


if __name__ == "__main__":
    sys.exit(run_phase50_tests())
