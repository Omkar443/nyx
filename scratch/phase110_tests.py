#!/usr/bin/env python3
"""
Phase 11.0 — NYX Core Decoupling & Service Architecture Guard Test Suite
"""
import glob
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def run_cli(args, cwd):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    cmd = [sys.executable, "-m", "nyx_cli.cli"] + args
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr


def run_phase110_tests():
    test_dir = REPO_ROOT / "test-phase110-workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 11.0 NYX DECOUPLING & ARCHITECTURE TESTS")
    print("==================================================")

    # 1. Import Safety Verification
    try:
        import nyx
        import nyx.api
        import nyx.application
        import nyx.core
        import nyx.execution
        import nyx.infrastructure
        import nyx.interface
        import nyx.models
        import nyx.recon
        import nyx.security
        import nyx.validation
        results["1_import_safety"] = True
    except Exception as e:
        print(f"Import safety error: {e}")
        results["1_import_safety"] = False

    # 2. Coupling Inventory (nyx -> nyx_cli.cli imports)
    nyx_py_files = glob.glob(str(REPO_ROOT / "nyx" / "**" / "*.py"), recursive=True)
    nyx_imports = []
    direct_core_nyx_imports = []
    for fpath in nyx_py_files:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
            for line_no, line in enumerate(fp, 1):
                if "nyx_cli.cli" in line or "from nyx_cli" in line:
                    item = f"{Path(fpath).relative_to(REPO_ROOT)}:{line_no}: {line.strip()}"
                    nyx_imports.append(item)
                    if "nyx\\core" in fpath or "nyx/core" in fpath:
                        direct_core_nyx_imports.append(item)

    print(f"Total nyx -> nyx_cli.cli imports: {len(nyx_imports)}")
    print(f"Direct nyx/core -> nyx_cli.cli imports: {len(direct_core_nyx_imports)}")
    results["2_dependency_decoupling"] = (len(direct_core_nyx_imports) == 0)

    # 3. Application Services Instantiation and Core Functionality
    try:
        from nyx.application.analysis_service import AnalysisService
        from nyx.application.engagement_service import EngagementService
        from nyx.application.evidence_service import EvidenceService
        from nyx.application.finding_service import FindingService
        from nyx.application.mission_service import MissionService
        from nyx.application.recon_service import ReconService
        from nyx.application.skill_service import SkillService
        from nyx.application.validation_service import ValidationService

        eng_svc = EngagementService()
        rec_svc = ReconService()
        find_svc = FindingService()
        ev_svc = EvidenceService()
        ana_svc = AnalysisService()
        val_svc = ValidationService()
        mis_svc = MissionService()
        skl_svc = SkillService()

        skills = skl_svc.list_skills()
        results["3_service_instantiation"] = (
            eng_svc is not None and
            rec_svc is not None and
            find_svc is not None and
            ev_svc is not None and
            ana_svc is not None and
            val_svc is not None and
            mis_svc is not None and
            skl_svc is not None and
            isinstance(skills, list) and len(skills) > 0
        )
    except Exception as e:
        print(f"Service instantiation error: {e}")
        results["3_service_instantiation"] = False

    # 4. Security Invariants: Authorization & Scope
    from nyx.security.authorization import check_authorization, is_hostname_in_scope, sanitize_canonical_evidence

    old_cwd = os.getcwd()
    os.chdir(test_dir)

    eng_svc.init_engagement("example.com")
    auth_ok, auth_msg = check_authorization()
    scope_ok = is_hostname_in_scope("app.example.com", ["*.example.com"])
    scope_fail = is_hostname_in_scope("evil.com", ["*.example.com"])
    results["4_security_authorization_scope"] = (auth_ok and scope_ok and not scope_fail)

    # 5. Security Invariants: Evidence Sanitization & SHA-256 Integrity
    san_res = sanitize_canonical_evidence("Authorization: Bearer secret12345")
    from nyx.infrastructure.filesystem import calculate_file_hash
    tmp_file = test_dir / "test_hash.txt"
    tmp_file.write_text("NYX Integrity Verification", encoding="utf-8")
    hash_val = calculate_file_hash(tmp_file)

    results["5_security_sanitization_hash"] = (
        san_res.status == "sanitized" and
        "[REDACTED]" in san_res.content and
        "secret12345" not in san_res.content and
        len(hash_val) == 64
    )

    # 6. Security Invariants: State Machine Gate
    from nyx.core import engagement
    rc_report_blocked = run_cli(["report", "FH-2026-001"], cwd=test_dir)[0] != 0
    engagement.set_state("ANALYSIS")
    engagement.set_state("VALIDATION")
    engagement.set_state("REPORTING")
    results["6_state_machine_invariants"] = rc_report_blocked

    # 7. CLI Compatibility Verifications
    engagement.set_state("DISCOVERY", force_state=True)
    run_cli(["engagement", "init", "example.com"], cwd=test_dir)
    run_cli(["finding", "create", "--title", "Test Finding", "--endpoint", "example.com"], cwd=test_dir)

    cli_commands = [
        ["--version"],
        ["--help"],
        ["engagement", "status"],
        ["recon", "example.com"],
        ["skills", "list"],
        ["evidence", "list", "FH-2026-001"],
        ["findings"],
        ["mission", "--help"]
    ]
    cli_results = []
    for cmd in cli_commands:
        rc, out, err = run_cli(cmd, cwd=test_dir)
        cli_results.append(rc == 0)

    results["7_cli_compatibility"] = all(cli_results)

    os.chdir(old_cwd)
    if test_dir.exists():
        shutil.rmtree(test_dir)

    print("\n==================================================")
    passed_cnt = 0
    for k, v in results.items():
        status = "PASS" if v else "FAIL"
        if v:
            passed_cnt += 1
        print(f"[{k}] {status}")
    print("==================================================")
    print(f" TOTAL VERIFICATIONS PASSED: {passed_cnt} / {len(results)}")
    print(f" OVERALL PHASE 11.0 SUITE RESULT: {'PASS' if passed_cnt == len(results) else 'FAIL'}")
    print("==================================================")

    return 0 if passed_cnt == len(results) else 1


if __name__ == "__main__":
    sys.exit(run_phase110_tests())
