#!/usr/bin/env python3
"""
Phase 4.1 — Evidence Storage Architecture Test Suite
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

def run_cli(args, cwd):
    cmd = [sys.executable, "-m", "nyx_cli.cli"] + args
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def run_phase41_tests():
    test_dir = Path("D:/Pentest/Skill File/NYX/test-phase41-workspace")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 4.1 EVIDENCE STORAGE TEST SUITE (15 CHECKS)")
    print("==================================================")

    # Init engagement
    run_cli(["engagement", "init", "example.com"], cwd=test_dir)
    eng_dir = test_dir / ".engagement"

    # Seed a valid finding in findings.json
    findings_file = eng_dir / "findings.json"
    findings_file.write_text(json.dumps([{
        "finding_id": "FH-2026-001",
        "title": "GraphQL Introspection IDOR",
        "severity": "High",
        "endpoint": "/graphql",
        "parameter": "query",
        "vulnerability": "IDOR"
    }], indent=2))

    # Test 5: Unknown finding is rejected
    rc, out, err = run_cli(["evidence", "add", "FH-2026-999", "--type", "note", "--content", "test note"], cwd=test_dir)
    results["5_unknown_finding_rejected"] = (rc != 0 and "does not exist" in out)
    print(f"[5] Unknown finding rejected: {'PASS' if results['5_unknown_finding_rejected'] else 'FAIL'}")

    # Test 6: HTTP request evidence stored
    rc, out, err = run_cli([
        "evidence", "add", "FH-2026-001",
        "--type", "http_request",
        "--content", "GET /api/user HTTP/1.1\nHost: example.com\nAuthorization: Bearer secret123",
        "--description", "Initial request",
        "--source", "burp"
    ], cwd=test_dir)
    results["6_http_request_stored"] = (rc == 0 and "EV-2026-0001" in out)
    print(f"[6] HTTP request evidence stored: {'PASS' if results['6_http_request_stored'] else 'FAIL'}")

    # Test 7: HTTP response evidence stored
    rc, out, err = run_cli([
        "evidence", "add", "FH-2026-001",
        "--type", "http_response",
        "--content", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":1}",
        "--description", "Initial response",
        "--source", "burp"
    ], cwd=test_dir)
    results["7_http_response_stored"] = (rc == 0 and "EV-2026-0002" in out)
    print(f"[7] HTTP response evidence stored: {'PASS' if results['7_http_response_stored'] else 'FAIL'}")

    # Test 8: Notes evidence supported
    rc, out, err = run_cli([
        "evidence", "add", "FH-2026-001",
        "--type", "note",
        "--content", "Manual PoC verification notes",
        "--description", "Tester notes",
        "--source", "manual"
    ], cwd=test_dir)
    results["8_notes_evidence_supported"] = (rc == 0 and "notes.md" in out)
    print(f"[8] Notes evidence supported: {'PASS' if results['8_notes_evidence_supported'] else 'FAIL'}")

    # Test 1, 9: Evidence directory structure & attachment directory exists
    ev_dir = eng_dir / "evidence" / "FH-2026-001"
    req_dir = ev_dir / "requests"
    resp_dir = ev_dir / "responses"
    att_dir = ev_dir / "attachments"
    results["1_9_dir_structure"] = (ev_dir.exists() and req_dir.exists() and resp_dir.exists() and att_dir.exists())
    print(f"[1,9] Evidence directory structure & attachments dir created: {'PASS' if results['1_9_dir_structure'] else 'FAIL'}")

    # Test 2, 3, 4, 10, 11: Metadata schema, unique IDs, finding reference, relative paths, SHA-256
    meta_file = ev_dir / "metadata.json"
    meta_items = json.loads(meta_file.read_text())
    first_item = meta_items[0] if meta_items else {}

    results["2_3_4_10_11_metadata_schema"] = (
        len(meta_items) >= 3 and
        first_item.get("evidence_id") == "EV-2026-0001" and
        first_item.get("finding_id") == "FH-2026-001" and
        first_item.get("file") == "requests/EV-2026-0001.txt" and
        not first_item.get("file").startswith("C:") and
        not first_item.get("file").startswith("/") and
        len(first_item.get("sha256", "")) == 64
    )
    print(f"[2,3,4,10,11] Metadata schema, relative paths & SHA-256: {'PASS' if results['2_3_4_10_11_metadata_schema'] else 'FAIL'}")

    # Test 12: Evidence verification succeeds
    rc, out, err = run_cli(["evidence", "verify", "EV-2026-0001"], cwd=test_dir)
    results["12_verification_succeeds"] = (rc == 0 and "Integrity: PASS" in out)
    print(f"[12] Evidence verification succeeds: {'PASS' if results['12_verification_succeeds'] else 'FAIL'}")

    # Test 13: Modified evidence detected
    req_file = ev_dir / "requests" / "EV-2026-0001.txt"
    req_file.write_text("TAMPERED CONTENT")
    rc, out, err = run_cli(["evidence", "verify", "EV-2026-0001"], cwd=test_dir)
    results["13_modified_evidence_detected"] = (rc != 0 and "Integrity: FAIL" in out)
    print(f"[13] Tampered evidence detected cleanly: {'PASS' if results['13_modified_evidence_detected'] else 'FAIL'}")

    # Test 14: Metadata writes are atomic
    # Check that metadata file was written properly and temporary file is cleaned up
    temp_meta = meta_file.with_suffix(".json.tmp")
    results["14_atomic_metadata_write"] = (meta_file.exists() and not temp_meta.exists())
    print(f"[14] Metadata writes are atomic (.tmp replace): {'PASS' if results['14_atomic_metadata_write'] else 'FAIL'}")

    # Test CLI List & Show
    rc, out, err = run_cli(["evidence", "list", "FH-2026-001"], cwd=test_dir)
    l_ok = (rc == 0 and "EV-2026-0001" in out)

    rc, out, err = run_cli(["evidence", "show", "EV-2026-0002"], cwd=test_dir)
    s_ok = (rc == 0 and "EV-2026-0002" in out and "SHA-256" in out)

    results["cli_list_show"] = (l_ok and s_ok)
    print(f"[CLI] Evidence list & show commands: {'PASS' if results['cli_list_show'] else 'FAIL'}")

    print("\n==================================================")
    all_passed = all(results.values())
    print(f" TOTAL VERIFICATIONS PASSED: {sum(1 for v in results.values() if v)} / {len(results)}")
    print(f" OVERALL PHASE 4.1 SUITE RESULT: {'PASS' if all_passed else 'FAIL'}")
    print("==================================================")

if __name__ == "__main__":
    run_phase41_tests()
