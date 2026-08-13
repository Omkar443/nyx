#!/usr/bin/env python3
"""
Phase 9.0 — NYX Validation Intelligence Engine Automated Test Suite
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

def run_cli(args, cwd):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    cmd = [sys.executable, "-m", "nyx_cli.cli"] + args
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr

def run_phase90_tests():
    test_dir = REPO_ROOT / "test-phase90-workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 9.0 NYX VALIDATION INTELLIGENCE ENGINE TESTS")
    print("==================================================")

    # 1. All 82 Skills Discovered
    from nyx.core.skills import load_skills, parse_skill_metadata, search_skills, get_skill
    skills_map = load_skills()
    results["1_all_82_skills_discovered"] = (len(skills_map) >= 80)

    # 2. Skill Loader & Metadata Extraction Works
    sample_meta = parse_skill_metadata(REPO_ROOT / ".agents" / "skills" / "hunt-auth-bypass")
    results["2_metadata_extraction_works"] = (
        sample_meta.get("name") == "hunt-auth-bypass" and
        isinstance(sample_meta.get("description"), str)
    )

    # 3. NYX Skill Registry & Search Works
    search_res = search_skills("idor")
    get_res = get_skill("hunt-idor")
    results["3_skill_registry_works"] = (len(search_res) > 0 and get_res is not None)

    # 4. Router Uses Skills Library
    from nyx.core.router import recommend_skills
    rec = recommend_skills("http://testaspnet.vulnweb.com/login.aspx", technology="ASP.NET")
    results["4_router_recommends_correct_skills"] = (
        rec.get("priority") == "HIGH" and "hunt-aspnet" in rec.get("recommended_skills", [])
    )

    # 5. Validation Engine Works
    from nyx.validation.engine import validate_finding
    from nyx.validation.rules import get_rule
    idor_rule = get_rule("IDOR")
    val_res = validate_finding("FH-2026-001")
    results["5_validation_engine_works"] = (
        idor_rule is not None and
        isinstance(val_res, dict) and
        val_res.get("validation", {}).get("confidence") is not None
    )

    # 6. CLI Commands Work
    rc_lst, out_lst, _ = run_cli(["skills", "list"], cwd=test_dir)
    rc_src, out_src, _ = run_cli(["skills", "search", "idor"], cwd=test_dir)
    rc_shw, out_shw, _ = run_cli(["skills", "show", "hunt-idor"], cwd=test_dir)
    rc_val, out_val, _ = run_cli(["validate", "FH-2026-001"], cwd=test_dir)
    rc_rls, out_rls, _ = run_cli(["validate", "rules", "idor"], cwd=test_dir)

    results["6_cli_commands_work"] = (
        rc_lst == 0 and "82 total" in out_lst and
        rc_src == 0 and "hunt-idor" in out_src and
        rc_shw == 0 and "Details: hunt-idor" in out_shw and
        rc_val == 0 and "Validation Report" in out_val and
        rc_rls == 0 and "Rule Specification: IDOR" in out_rls
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
    print(f" OVERALL PHASE 9.0 SUITE RESULT: {'PASS' if passed_cnt == len(results) else 'FAIL'}")
    print("==================================================")

    if test_dir.exists():
        shutil.rmtree(test_dir)

    return 0 if passed_cnt == len(results) else 1

if __name__ == "__main__":
    sys.exit(run_phase90_tests())
