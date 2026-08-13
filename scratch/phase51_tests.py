#!/usr/bin/env python3
"""
Phase 5.1 — NYX Branding Migration Automated Test Suite
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from nyx_cli.cli import APP_NAME, VERSION, main


import os

def run_cli(args, cwd):
    cmd = [sys.executable, "-m", "nyx_cli.cli"] + args
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def run_phase51_tests():
    test_dir = REPO_ROOT / "test-phase51-workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 5.1 NYX BRANDING MIGRATION TEST SUITE")
    print("==================================================")

    # 1. Version Output
    rc_v, out_v, _ = run_cli(["--version"], cwd=test_dir)
    results["1_version_output"] = (rc_v == 0 and APP_NAME in out_v and VERSION in out_v)

    # 2. Help Output (nyx)
    rc_h, out_h, _ = run_cli(["--help"], cwd=test_dir)
    results["2_help_output"] = (rc_h == 0 and "nyx" in out_h and "NYX Security Intelligence Engine" in out_h)

    # 3. Backward Compatibility Alias (nyx)
    cmd_alias = [sys.executable, "-c", "import sys; sys.argv=['nyx', '--version']; from nyx_cli.cli import main; main()"]
    env_alias = dict(os.environ)
    env_alias["PYTHONPATH"] = str(REPO_ROOT)
    p_alias = subprocess.run(cmd_alias, cwd=test_dir, capture_output=True, text=True, env=env_alias)
    results["3_nyx_alias_works"] = (p_alias.returncode == 0 and APP_NAME in p_alias.stdout)

    # 4. pyproject.toml Metadata
    pyproject_p = REPO_ROOT / "pyproject.toml"
    pyproject_text = pyproject_p.read_text(encoding="utf-8") if pyproject_p.exists() else ""
    results["4_pyproject_metadata"] = (
        'name = "nyx-security-engine"' in pyproject_text and
        'nyx = "nyx_cli.cli:main"' in pyproject_text and
        'nyx = "nyx_cli.cli:main"' in pyproject_text
    )

    # 5. GEMINI.md NYX Architecture
    gemini_p = REPO_ROOT / "GEMINI.md"
    gemini_text = gemini_p.read_text(encoding="utf-8") if gemini_p.exists() else ""
    results["5_gemini_architecture"] = (
        "NYX Security Intelligence Engine" in gemini_text and
        "Google Antigravity" in gemini_text and
        "Architecture Overview" in gemini_text and
        "nyx recon" in gemini_text
    )

    # 6. Check active GEMINI.md for obsolete branding
    results["6_gemini_no_obsolete_branding"] = ("NYX Security Intelligence Engine" not in gemini_text and "Claude Code" not in gemini_text)

    # 7. Engagement execution under nyx
    rc_init, out_init, _ = run_cli(["engagement", "init", "nyxtest.local"], cwd=test_dir)
    rc_st, out_st, _ = run_cli(["state", "ANALYSIS"], cwd=test_dir)
    results["7_nyx_engagement_and_state"] = (rc_init == 0 and rc_st == 0 and "nyxtest.local" in out_init)

    print("\n==================================================")
    passed_cnt = 0
    for k, v in results.items():
        status = "PASS" if v else "FAIL"
        if v:
            passed_cnt += 1
        print(f"[{k}] {status}")
    print("==================================================")
    print(f" TOTAL VERIFICATIONS PASSED: {passed_cnt} / {len(results)}")
    print(f" OVERALL PHASE 5.1 SUITE RESULT: {'PASS' if passed_cnt == len(results) else 'FAIL'}")
    print("==================================================")

    if test_dir.exists():
        shutil.rmtree(test_dir)

    return 0 if passed_cnt == len(results) else 1


if __name__ == "__main__":
    sys.exit(run_phase51_tests())
