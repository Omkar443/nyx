#!/usr/bin/env python3
"""
Full Stage-2 Integration Audit Script
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

def run_cli(args, cwd):
    cmd = [sys.executable, "-m", "nyx_cli.cli"] + args
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def run_audit():
    test_dir = Path("D:/Pentest/Skill File/NYX/test-audit-target")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)
    
    results = {}
    print("==================================================")
    print(" STAGE 2 FULL INTEGRATION AUDIT & DISCOVERY WORKFLOW")
    print("==================================================")
    
    # A & 1. Init
    rc, out, err = run_cli(["engagement", "init", "integration-test.local"], cwd=test_dir)
    eng_dir = test_dir / ".engagement"
    req_files = ["target.yaml", "authorization.yaml", "state.json", "technologies.json", "endpoints.json", "tested_vectors.json", "findings.json", "notes.md"]
    created_files = [p.name for p in eng_dir.glob("*")]
    all_present = all(f in created_files for f in req_files)
    results["A_init_files"] = (rc == 0 and all_present)
    print(f"[A] Init files creation: {'PASS' if results['A_init_files'] else 'FAIL'}")

    # B & C. Auth Check
    auth_yaml = eng_dir / "authorization.yaml"
    results["B_C_auth_exists"] = auth_yaml.exists() and "authorized: true" in auth_yaml.read_text()
    print(f"[B/C] Authorization file check: {'PASS' if results['B_C_auth_exists'] else 'FAIL'}")

    # D. Current State detection (DISCOVERY)
    rc, out, err = run_cli(["state"], cwd=test_dir)
    results["D_state_discovery"] = "DISCOVERY" in out
    print(f"[D] State detection (DISCOVERY): {'PASS' if results['D_state_discovery'] else 'FAIL'}")

    # E & F. Add Endpoint & Tech (DISCOVERY -> ANALYSIS)
    run_cli(["memory", "add", "--type", "endpoint", "--value", "https://integration-test.local/graphql", "--priority", "P1"], cwd=test_dir)
    run_cli(["memory", "add", "--type", "technology", "--category", "APIs", "--value", "GraphQL"], cwd=test_dir)
    
    rc, out, err = run_cli(["state", "ANALYSIS"], cwd=test_dir)
    results["J_state_transition_1"] = (rc == 0)
    
    rc, out, err = run_cli(["technology", "map", "graphql"], cwd=test_dir)
    results["E_tech_map_graphql"] = ("hunt-graphql" in out and "hunt-idor" in out)
    print(f"[E] Tech mapping -> hunt-graphql selection: {'PASS' if results['E_tech_map_graphql'] else 'FAIL'}")

    rc, out, err = run_cli(["memory", "search", "integration-test.local"], cwd=test_dir)
    results["F_endpoints_in_analysis"] = ("endpoints.json" in out)
    print(f"[F] Endpoint persisted & found in analysis: {'PASS' if results['F_endpoints_in_analysis'] else 'FAIL'}")

    # G. Vector Persistence (ANALYSIS -> VALIDATION)
    run_cli(["memory", "add", "--type", "vector", "--value", "IDOR_query_user_by_id"], cwd=test_dir)
    rc, out, err = run_cli(["memory", "search", "IDOR_query_user_by_id"], cwd=test_dir)
    results["G_tested_vectors"] = ("tested_vectors.json" in out)
    print(f"[G] Tested vector persistence: {'PASS' if results['G_tested_vectors'] else 'FAIL'}")

    run_cli(["state", "VALIDATION"], cwd=test_dir)

    # H & I. Finding persistence & Duplicate Check
    findings_file = eng_dir / "findings.json"
    finding_obj = [
        {
            "finding_id": "FH-2026-001",
            "title": "GraphQL Introspection IDOR on User Endpoint",
            "severity": "High",
            "CWE": "CWE-639",
            "VRT": "Broken Object Level Authorization (IDOR)",
            "endpoint": "/graphql",
            "parameter": "query",
            "vulnerability": "IDOR",
            "evidence": "query { user(id: 100) { email } }",
            "status": "Confirmed",
            "remediation": "Enforce field and object authorization."
        }
    ]
    findings_file.write_text(json.dumps(finding_obj, indent=2))

    rc, out, err = run_cli(["findings"], cwd=test_dir)
    results["H_findings_persist"] = ("FH-2026-001" in out)
    print(f"[H] Finding persistence: {'PASS' if results['H_findings_persist'] else 'FAIL'}")

    rc, out, err = run_cli(["duplicate-check", "--endpoint", "/graphql", "--parameter", "query", "--vulnerability", "IDOR"], cwd=test_dir)
    results["I_duplicate_check"] = (rc == 1 and "Possible duplicate finding detected" in out)
    print(f"[I] Duplicate check detection: {'PASS' if results['I_duplicate_check'] else 'FAIL'}")

    # K. Report generation from stored finding (VALIDATION -> REPORTING)
    run_cli(["state", "REPORTING"], cwd=test_dir)
    report_file = test_dir / "report_draft.md"
    rc, out, err = run_cli(["report", "FH-2026-001", "--platform", "bugcrowd", "--out", str(report_file)], cwd=test_dir)
    results["K_report_from_stored"] = (rc == 0 and report_file.exists() and "GraphQL Introspection IDOR" in report_file.read_text())
    print(f"[K] Report consumes stored finding: {'PASS' if results['K_report_from_stored'] else 'FAIL'}")

    # L. Export
    rc, out, err = run_cli(["engagement", "export"], cwd=test_dir)
    export_files = list(test_dir.glob("engagement_export_*.json"))
    results["L_export"] = (rc == 0 and len(export_files) > 0 and "FH-2026-001" in export_files[0].read_text())
    print(f"[L] Complete engagement export: {'PASS' if results['L_export'] else 'FAIL'}")

    # M. Sensitive information redaction
    run_cli(["memory", "add", "--type", "endpoint", "--value", "https://target.com/login?password=SecretPass123&token=Bearer xyz123"], cwd=test_dir)
    rc, out, err = run_cli(["memory", "search", "SecretPass123"], cwd=test_dir)
    results["M_redaction"] = ("SecretPass123" not in out and "REDACTED" in (eng_dir / "endpoints.json").read_text())
    print(f"[M] Sensitive information redaction: {'PASS' if results['M_redaction'] else 'FAIL'}")

    print("\n--- Testing Failure Conditions ---")
    
    # Fail 1: Invalid State
    rc, out, err = run_cli(["state", "INVALID_STATE"], cwd=test_dir)
    f1 = (rc != 0 and ("invalid choice" in err.lower() or "invalid state" in out.lower() or "invalid state" in err.lower()))
    print(f"[Fail 1] Invalid state transition handling: {'PASS' if f1 else 'FAIL'}")

    # Fail 2: Malformed findings.json
    findings_file.write_text("{malformed_json:")
    rc, out, err = run_cli(["findings"], cwd=test_dir)
    f2 = (rc != 0 and "Malformed findings.json" in out)
    print(f"[Fail 2] Malformed findings.json handling: {'PASS' if f2 else 'FAIL'}")

    # Reset valid finding
    findings_file.write_text(json.dumps(finding_obj, indent=2))

    # Fail 3: Duplicate finding check returns warning code 1
    rc, out, err = run_cli(["duplicate-check", "--endpoint", "/graphql", "--parameter", "query", "--vulnerability", "IDOR"], cwd=test_dir)
    f3 = (rc == 1)
    print(f"[Fail 3] Duplicate finding warning exit code: {'PASS' if f3 else 'FAIL'}")

    # Fail 4: Missing finding for report
    rc, out, err = run_cli(["report", "FH-NONEXISTENT"], cwd=test_dir)
    f4 = (rc != 0 and "not found" in out)
    print(f"[Fail 4] Nonexistent finding report handling: {'PASS' if f4 else 'FAIL'}")

    print("\n==================================================")
    print(" ALL AUDIT CHECKS COMPLETE")
    print("==================================================")

if __name__ == "__main__":
    run_audit()
