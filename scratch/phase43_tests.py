#!/usr/bin/env python3
"""
Phase 4.3 — Finding Lifecycle Management Dedicated Test Suite (22 Checks)
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import os

def run_cli(args, cwd):
    cmd = [sys.executable, "-m", "nyx_cli.cli"] + args
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def run_phase43_tests():
    test_dir = Path("D:/Pentest/Skill File/NYX/test-phase43-workspace")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 4.3 FINDING LIFECYCLE MANAGEMENT TESTS")
    print("==================================================")

    # Init engagement
    run_cli(["engagement", "init", "example.com"], cwd=test_dir)
    eng_dir = test_dir / ".engagement"

    # 1, 2, 3, 4, 5: Create finding, check dir, finding.json schema, HYPOTHESIS initial state, timeline created
    rc, out, err = run_cli([
        "finding", "create",
        "--title", "Possible IDOR on User Endpoint Authorization Bearer secret123",
        "--endpoint", "/api/user/100",
        "--parameter", "id",
        "--tag", "authorization",
        "--description", "Testing IDOR vulnerability"
    ], cwd=test_dir)

    f_dir = eng_dir / "findings" / "FH-2026-001"
    f_json = f_dir / "finding.json"
    t_json = f_dir / "timeline.json"
    h_json = f_dir / "hypotheses.json"
    n_md = f_dir / "notes.md"

    results["1_2_creation_and_dir"] = (rc == 0 and "FH-2026-001" in out and f_dir.exists())

    if f_json.exists():
        fdata = json.loads(f_json.read_text())
        results["3_finding_schema"] = (
            fdata.get("finding_id") == "FH-2026-001" and
            "status" in fdata and
            "created_at" in fdata and
            "updated_at" in fdata and
            "evidence_ids" in fdata and
            "tags" in fdata
        )
        results["4_initial_hypothesis_state"] = (fdata.get("status") == "HYPOTHESIS")
    else:
        results["3_finding_schema"] = False
        results["4_initial_hypothesis_state"] = False

    if t_json.exists():
        tdata = json.loads(t_json.read_text())
        results["5_timeline_created"] = (len(tdata) >= 1 and tdata[0].get("to") == "HYPOTHESIS")
    else:
        results["5_timeline_created"] = False

    # 6. Hypothesis storage works
    rc, out, err = run_cli([
        "finding", "hypothesis", "add", "FH-2026-001",
        "--type", "IDOR",
        "--description", "User ID parameter may lack authorization check"
    ], cwd=test_dir)
    if h_json.exists():
        hdata = json.loads(h_json.read_text())
        results["6_hypothesis_storage"] = (rc == 0 and len(hdata) >= 1 and hdata[0].get("id") == "HY-001")
    else:
        results["6_hypothesis_storage"] = False

    # 7. Valid transition: HYPOTHESIS -> INVESTIGATING
    rc, out, err = run_cli([
        "finding", "transition", "FH-2026-001", "INVESTIGATING",
        "--reason", "Beginning active testing"
    ], cwd=test_dir)
    results["7_trans_investigating"] = (rc == 0 and "INVESTIGATING" in out)

    # 8. Valid transition: INVESTIGATING -> VALIDATED
    rc, out, err = run_cli([
        "finding", "transition", "FH-2026-001", "VALIDATED",
        "--reason", "Demonstrated unauthorized profile access"
    ], cwd=test_dir)
    results["8_trans_validated"] = (rc == 0 and "VALIDATED" in out)

    # 9. Valid transition: VALIDATED -> CONFIRMED
    rc, out, err = run_cli([
        "finding", "transition", "FH-2026-001", "CONFIRMED",
        "--reason", "Reproduced consistently across multiple accounts"
    ], cwd=test_dir)
    results["9_trans_confirmed"] = (rc == 0 and "CONFIRMED" in out)

    # 10. Valid transition: CONFIRMED -> REPORTED
    rc, out, err = run_cli([
        "finding", "transition", "FH-2026-001", "REPORTED",
        "--reason", "Submitted report to program"
    ], cwd=test_dir)
    results["10_trans_reported"] = (rc == 0 and "REPORTED" in out)

    # 11, 12. Rejected path & Invalid transition blocked
    # Create second finding for REJECTED test
    run_cli(["finding", "create", "--title", "False Positive SQLi", "--endpoint", "/search"], cwd=test_dir)
    rc, out, err = run_cli(["finding", "transition", "FH-2026-002", "REPORTED", "--reason", "Shortcut jump"], cwd=test_dir)
    results["12_invalid_trans_blocked"] = (rc != 0 and "Invalid finding transition" in out)

    rc, out, err = run_cli(["finding", "reject", "FH-2026-002", "--reason", "Parameter is sanitized safely"], cwd=test_dir)
    results["11_rejected_path"] = (rc == 0 and "REJECTED" in out)

    # 13. Timeline updates correctly
    tdata = json.loads((eng_dir / "findings" / "FH-2026-001" / "timeline.json").read_text())
    results["13_timeline_updates"] = (len(tdata) >= 5)

    # 14. Finding list works
    rc, out, err = run_cli(["finding", "list"], cwd=test_dir)
    results["14_finding_list"] = (rc == 0 and "FH-2026-001" in out and "FH-2026-002" in out)

    # 15. Finding show works
    rc, out, err = run_cli(["finding", "show", "FH-2026-001"], cwd=test_dir)
    results["15_finding_show"] = (rc == 0 and "FH-2026-001" in out and "REPORTED" in out)

    # 16. History display works
    rc, out, err = run_cli(["finding", "history", "FH-2026-001"], cwd=test_dir)
    results["16_history_display"] = (rc == 0 and "INVESTIGATING" in out and "REPORTED" in out)

    # 17, 18. Evidence attachment & unknown evidence rejection
    # Add real evidence first to FH-2026-001
    run_cli(["evidence", "add", "FH-2026-001", "--type", "note", "--content", "Proof note"], cwd=test_dir)
    ev_meta = json.loads((eng_dir / "evidence" / "FH-2026-001" / "metadata.json").read_text())
    valid_eid = ev_meta[0]["evidence_id"]

    rc, out, err = run_cli(["finding", "attach", "FH-2026-001", valid_eid], cwd=test_dir)
    results["17_evidence_attached"] = (rc == 0 and valid_eid in out)

    rc, out, err = run_cli(["finding", "attach", "FH-2026-001", "EV-2026-9999"], cwd=test_dir)
    results["18_unknown_evidence_rejected"] = (rc != 0 and "Unknown evidence ID" in out)

    # 19. Sensitive data cannot persist in finding files
    fdata_raw = (eng_dir / "findings" / "FH-2026-001" / "finding.json").read_text()
    results["19_sensitive_data_redacted"] = ("secret123" not in fdata_raw and "[REDACTED]" in fdata_raw)

    print("\n==================================================")
    for k, v in results.items():
        print(f"[{k}] {'PASS' if v else 'FAIL'}")
    all_passed = all(results.values())
    print(f"\n TOTAL VERIFICATIONS PASSED: {sum(1 for v in results.values() if v)} / {len(results)}")
    print(f" OVERALL PHASE 4.3 SUITE RESULT: {'PASS' if all_passed else 'FAIL'}")
    print("==================================================")

if __name__ == "__main__":
    run_phase43_tests()
