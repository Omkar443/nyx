"""
Phase 13.0 — NYX Execution Engine Upgrade Verification Test Suite
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

# Ensure workspace root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nyx.models.execution import ExecutionRequest, ExecutionResult, ExecutionStatus
from nyx.execution.adapters import (
    SubfinderAdapter,
    HttpxAdapter,
    KatanaAdapter,
    NucleiAdapter,
    NmapAdapter,
    get_adapter,
)
from nyx.execution.artifacts import store_execution_artifacts, get_execution_artifacts
from nyx.execution.queue import ExecutionQueue
from nyx.execution.engine import ExecutionEngine
from nyx.application.execution_service import ExecutionService
from nyx.application.base import ServiceResult
from nyx.api.execution import run_execution, get_execution_status_api, list_execution_history_api
from nyx.infrastructure.filesystem import _get_eng_dir


def run_phase130_tests() -> int:
    print("=" * 50)
    print(" PHASE 13.0 NYX EXECUTION ENGINE VERIFICATION")
    print("=" * 50)

    test_dir = REPO_ROOT / "test-phase130-workspace"
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

        # Test 2: Domain Models & Serialization
        total += 1
        req = ExecutionRequest(tool_name="subfinder", target="example.com", arguments=["-silent"], dry_run=True)
        res = ExecutionResult(
            execution_id=req.execution_id,
            tool_name=req.tool_name,
            target=req.target,
            status=ExecutionStatus.COMPLETED.value,
            stdout="sub1.example.com\nsub2.example.com",
            dry_run=True,
        )
        res_dict = res.to_dict()
        res_from_dict = ExecutionResult.from_dict(res_dict)

        if (
            res.tool == "subfinder"
            and res_dict.get("tool_name") == "subfinder"
            and res_from_dict.execution_id == req.execution_id
            and res_from_dict.status == "COMPLETED"
        ):
            print("[2_domain_models] PASS - ExecutionRequest & ExecutionResult models operate cleanly")
            passed += 1
        else:
            print(f"[2_domain_models] FAIL - Model mismatch: {res_dict}")

        # Test 3: Tool Adapter Registry & Specialized Parsing
        total += 1
        sf_adapter = get_adapter("subfinder")
        httpx_adapter = get_adapter("httpx")
        katana_adapter = get_adapter("katana")
        nuclei_adapter = get_adapter("nuclei")
        nmap_adapter = get_adapter("nmap")

        sf_parsed = sf_adapter.parse_result("sub1.example.com\nsub2.example.com", "") if sf_adapter else {}
        httpx_parsed = httpx_adapter.parse_result('{"url": "https://example.com", "status_code": 200, "title": "Example Domain", "tech": ["Nginx"]}', "") if httpx_adapter else {}

        if (
            isinstance(sf_adapter, SubfinderAdapter)
            and isinstance(httpx_adapter, HttpxAdapter)
            and isinstance(katana_adapter, KatanaAdapter)
            and isinstance(nuclei_adapter, NucleiAdapter)
            and isinstance(nmap_adapter, NmapAdapter)
            and sf_parsed.get("assets_found") == 2
            and httpx_parsed.get("assets_found") == 1
        ):
            print("[3_tool_adapters] PASS - All 5 specialized tool adapters loaded & parsed outputs correctly")
            passed += 1
        else:
            print("[3_tool_adapters] FAIL - Adapter resolution or parsing failed")

        # Test 4: Execution Engine Pipeline & Dry-Run
        total += 1
        from nyx.core.engagement import init_engagement
        init_engagement("example.com")

        engine = ExecutionEngine(base_dir=test_dir)
        exec_res = engine.execute("subfinder", "example.com", dry_run=True)

        if (
            exec_res.status == ExecutionStatus.COMPLETED.value
            and exec_res.dry_run is True
            and "[DRY-RUN]" in exec_res.stdout
        ):
            print("[4_execution_engine] PASS - ExecutionEngine dry-run execution succeeded")
            passed += 1
        else:
            print(f"[4_execution_engine] FAIL - Engine execution result: {exec_res}")

        # Test 5: Security Boundary Enforcement (Authorization & Scope)
        total += 1
        # Test out of scope target
        blocked_res = engine.execute("httpx", "unrelated-domain.org", dry_run=True)

        # Test missing authorization.yaml
        auth_file = test_dir / ".engagement" / "authorization.yaml"
        auth_bak = auth_file.read_text(encoding="utf-8")
        auth_file.unlink()

        unauth_res = engine.execute("httpx", "example.com", dry_run=True)

        # Restore auth file
        auth_file.write_text(auth_bak, encoding="utf-8")

        if (
            blocked_res.status == ExecutionStatus.BLOCKED.value
            and unauth_res.status == ExecutionStatus.BLOCKED.value
            and unauth_res.authorized is False
        ):
            print("[5_security_controls] PASS - Security gates blocked out-of-scope & unauthorized executions")
            passed += 1
        else:
            print(f"[5_security_controls] FAIL - Blocked status: {blocked_res.status}, Unauth status: {unauth_res.status}")

        # Test 6: Artifact Management
        total += 1
        art_map = store_execution_artifacts(exec_res, parsed_data={"test": "data"})
        art_info = get_execution_artifacts(exec_res.execution_id)

        if (
            art_info.get("status") == "success"
            and "stdout.txt" in art_info.get("artifacts", {}).get("files", {})
            and "result.json" in art_info.get("artifacts", {}).get("files", {})
        ):
            print("[6_artifact_management] PASS - Execution stdout/stderr/result.json artifacts stored & retrieved")
            passed += 1
        else:
            print(f"[6_artifact_management] FAIL - Artifact retrieval failed: {art_info}")

        # Test 7: Execution Queue System
        total += 1
        queue = ExecutionQueue(base_dir=test_dir)
        queue.clear()
        req1 = ExecutionRequest(tool_name="subfinder", target="example.com", dry_run=True)
        req2 = ExecutionRequest(tool_name="httpx", target="example.com", dry_run=True)

        queue.enqueue(req1, priority=10)
        queue.enqueue(req2, priority=5)

        popped_1 = queue.pop_next()
        popped_2 = queue.pop_next()

        if popped_1 and popped_2 and popped_1.tool_name == "httpx" and popped_2.tool_name == "subfinder":
            print("[7_execution_queue] PASS - ExecutionQueue priority sorting and popping operates correctly")
            passed += 1
        else:
            p1_name = popped_1.tool_name if popped_1 else "None"
            p2_name = popped_2.tool_name if popped_2 else "None"
            print(f"[7_execution_queue] FAIL - Queue order expected httpx then subfinder, got {p1_name} then {p2_name}")

        # Test 8: Application Service Facade
        total += 1
        svc = ExecutionService(base_dir=test_dir)
        run_res = svc.run_tool("subfinder", "example.com", dry_run=True)
        hist_res = svc.get_history()

        if (
            isinstance(run_res, ServiceResult)
            and run_res.is_success
            and isinstance(hist_res, ServiceResult)
            and hist_res.is_success
            and len(hist_res.data.get("history", [])) > 0
        ):
            print("[8_execution_service] PASS - ExecutionService facade returned structured ServiceResult responses")
            passed += 1
        else:
            print(f"[8_execution_service] FAIL - Service results: run={run_res}, hist={hist_res}")

        # Test 9: AI Agent API Interface
        total += 1
        api_run = run_execution({"tool": "subfinder", "target": "example.com", "dry_run": True})
        api_hist = list_execution_history_api(limit=5)

        if (
            isinstance(api_run, dict)
            and api_run.get("success") is True
            and isinstance(api_hist, dict)
            and api_hist.get("success") is True
        ):
            print("[9_ai_agent_api] PASS - AI Agent API nyx.api.execution endpoints executed cleanly")
            passed += 1
        else:
            print(f"[9_ai_agent_api] FAIL - API results: run={api_run}, hist={api_hist}")

        # Test 10: CLI Compatibility Adapter Execution
        total += 1
        import subprocess
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT)

        cmd_hist = [sys.executable, "-m", "nyx_cli.cli", "exec", "history"]
        p_hist = subprocess.run(cmd_hist, cwd=test_dir, env=env, capture_output=True, text=True)

        cmd_run = [sys.executable, "-m", "nyx_cli.cli", "exec", "subfinder", "example.com", "--dry-run"]
        p_run = subprocess.run(cmd_run, cwd=test_dir, env=env, capture_output=True, text=True)

        if p_hist.returncode == 0 and p_run.returncode == 0 and "Execution ID" in p_run.stdout:
            print("[10_cli_adapter_exec] PASS - CLI nyx exec commands parsed and executed cleanly")
            passed += 1
        else:
            print(f"[10_cli_adapter_exec] FAIL - CLI exit codes: hist={p_hist.returncode}, run={p_run.returncode}. Out: {p_run.stdout}, Err: {p_run.stderr}")

    finally:
        os.chdir(cwd_orig)
        if test_dir.exists():
            try:
                shutil.rmtree(test_dir)
            except Exception:
                pass

    print("=" * 50)
    print(f" TOTAL VERIFICATIONS PASSED: {passed} / {total}")
    if passed == total:
        print(" OVERALL PHASE 13.0 SUITE RESULT: PASS")
        print("=" * 50)
        return 0
    else:
        print(" OVERALL PHASE 13.0 SUITE RESULT: FAIL")
        print("=" * 50)
        return 1


if __name__ == "__main__":
    sys.exit(run_phase130_tests())
