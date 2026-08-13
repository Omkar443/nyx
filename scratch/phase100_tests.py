#!/usr/bin/env python3
"""
Phase 10.0 — NYX Security Testing Orchestration & Controlled Tool Harness Test Suite
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


def run_phase100_tests():
    test_dir = REPO_ROOT / "test-phase100-workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 10.0 NYX CONTROLLED TOOL HARNESS TESTS")
    print("==================================================")

    # Setup engagement workspace
    from nyx.core import engagement
    old_cwd = os.getcwd()
    os.chdir(test_dir)
    engagement.init("example.com")

    # 1. Tool discovery
    from nyx.api.tools import load_tools_registry
    tools_reg = load_tools_registry().get("tools", {})
    results["1_tool_discovery"] = ("subfinder" in tools_reg and "httpx" in tools_reg)

    # 2. Command construction
    from nyx.execution.command import build_command
    valid, err, cmd_list = build_command("python", "example.com", ["-c"])
    results["2_command_construction"] = (valid and "python" in cmd_list[0])

    # 3. Dry-run
    from nyx.execution.executor import execute_tool
    dry_res = execute_tool("python", "example.com", extra_args=["-c"], dry_run=True)
    results["3_dry_run"] = (dry_res.dry_run and dry_res.exit_code == 0 and "DRY-RUN" in dry_res.stdout)

    # 4. Authorization enforcement
    from nyx.execution.policy import check_policy
    # Temporarily remove auth file
    d_dir = test_dir / ".engagement"
    auth_file = d_dir / "authorization.yaml"
    auth_file.write_text("authorized: false\n", encoding="utf-8")
    auth_ok, auth_msg, _ = check_policy("python", "example.com", execution_class="SAFE_ACTIVE")
    results["4_authorization_enforcement"] = (not auth_ok and "Authorization" in auth_msg)
    auth_file.write_text("authorized: true\n", encoding="utf-8")

    # 5. Scope enforcement (spoofing protection)
    scope_ok, scope_msg, scope_stat = check_policy("python", "evil-example.com", execution_class="SAFE_ACTIVE")
    results["5_scope_enforcement"] = (not scope_ok and scope_stat == "OUT_OF_SCOPE")

    # 6. Passive execution
    pas_res = execute_tool("python", "example.com", extra_args=["-c"], dry_run=True)
    results["6_passive_execution"] = (pas_res.authorized)

    # 7. Safe-active execution
    safe_res = execute_tool("python", "example.com", extra_args=["-c"], dry_run=True)
    results["7_safe_active_execution"] = (safe_res.authorized)

    # 8. Active execution blocked without authorization
    act_ok, act_msg, _ = check_policy("nuclei", "example.com", execution_class="ACTIVE", active_permitted=False)
    results["8_active_blocked_without_auth"] = (not act_ok and "ACTIVE" in act_msg)

    # 9. Timeout enforcement
    from nyx.execution.timeout import run_with_timeout
    code, out, err, timed_out = run_with_timeout([sys.executable, "-c", "import time; time.sleep(2)"], timeout_sec=1)
    results["9_timeout_enforcement"] = (timed_out and code == -1)

    # 10. Output capture
    from nyx.execution.sandbox import prepare_isolated_env
    code_c, out_c, err_c, _ = run_with_timeout([sys.executable, "-c", "print('hello_nyx')"], timeout_sec=5, env=prepare_isolated_env())
    results["10_output_capture"] = (code_c == 0 and "hello_nyx" in out_c)

    # 11. Output sanitization
    secret_out = "Authorization: Bearer secret_jwt_token_12345"
    from nyx_cli.cli import sanitize_canonical_evidence
    san_res = sanitize_canonical_evidence(secret_out)
    results["11_output_sanitization"] = ("[REDACTED]" in san_res.content and "secret_jwt_token" not in san_res.content)

    # 12. Evidence creation
    from nyx.core import findings, evidence
    findings.create("Test Finding", endpoint="https://example.com/api")
    f_list = findings.list_findings()
    f_id = f_list[0]["finding_id"] if f_list else "FH-SYSTEM"
    ev_res = evidence.add(f_id, ev_type="note", content="Sanitized output evidence", description="Test evidence")
    results["12_evidence_creation"] = (isinstance(ev_res, dict) and ev_res.get("evidence_id") is not None)

    # 13. SHA-256 integrity
    results["13_sha256_integrity"] = (isinstance(ev_res.get("sha256"), str) and len(ev_res.get("sha256")) == 64)

    # 14. Execution history
    db_file = d_dir / "database" / "executions.json"
    results["14_execution_history"] = (db_file.exists() and len(json.loads(db_file.read_text(encoding="utf-8"))) > 0)

    # 15. Missing tool handling
    m_val, m_err, _ = build_command("nonexistent_binary_xyz", "example.com")
    results["15_missing_tool_handling"] = (not m_val and "not found" in m_err)

    # 16. Malformed command handling
    mal_val, mal_err, _ = build_command("httpx", "example.com", extra_args=["--disallowed-flag-999"])
    results["16_malformed_command_handling"] = (not mal_val and "not in allowed_args" in mal_err)

    # 17. Out-of-scope target rejection
    out_ok, out_msg, _ = check_policy("python", "example.com.evil.com")
    results["17_out_of_scope_target_rejection"] = (not out_ok and "outside" in out_msg)

    # 18. Mission integration
    from nyx.api import mission
    rc_m = mission.run_mission("example.com")
    results["18_mission_integration"] = (rc_m == 0)

    # 19. Skill-to-tool mapping
    from nyx.core.skills import get_skill
    sk_info = get_skill("hunt-auth-bypass")
    results["19_skill_to_tool_mapping"] = (sk_info is not None and "required_tools" in sk_info)

    # 20. No raw credential persistence
    raw_ev = evidence.add(f_id, ev_type="http_request", content="Cookie: session=secret_cookie_999\r\n\r\n", description="Raw HTTP")
    ev_path = d_dir / "evidence" / f_id / raw_ev["file"]
    saved_content = ev_path.read_text(encoding="utf-8")
    results["20_no_raw_credential_persistence"] = ("secret_cookie_999" not in saved_content)

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
    print(f" OVERALL PHASE 10.0 SUITE RESULT: {'PASS' if passed_cnt == len(results) else 'FAIL'}")
    print("==================================================")

    return 0 if passed_cnt == len(results) else 1


if __name__ == "__main__":
    sys.exit(run_phase100_tests())
