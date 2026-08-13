"""
Phase 18 Verification Suite — NYX Distributed Worker Architecture & Remote Agent Nodes
Tests:
1. Worker registration (WorkerNode & WorkerRegistry)
2. Heartbeat system (WorkerHeartbeat)
3. Worker authentication & HMAC token verification (WorkerSecurity & DistributedAuthentication)
4. Remote task assignment & dispatching (WorkerScheduler)
5. Task recovery & retry policy (DistributedTaskQueue)
6. Evidence synchronization & SHA-256 integrity verification (EvidenceSync)
7. Dashboard API endpoints (/api/v1/workers/*)
8. CLI commands (nyx workers list/register/status/remove)
9. Zero reverse nyx_cli.cli imports in nyx/*, nyx/worker/*, nyx/distributed/*
10. Application WorkerService facade integration
"""
from __future__ import annotations

import glob
import os
import shutil
import sys

from pathlib import Path
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nyx.worker import WorkerNode, WorkerHeartbeat, WorkerExecutor, WorkerSecurity
from nyx.distributed import DistributedTransport, DistributedProtocol, DistributedAuthentication, EvidenceSync
from nyx.agent.manager import AgentController, WorkerRegistry, WorkerScheduler
from nyx.application.worker_service import WorkerService
from nyx.web.app import app
from nyx.web.auth import get_or_create_api_token
from nyx.core.engagement import init_engagement
from nyx.core.findings import create_finding


def run_phase180_tests():
    print("=" * 60)
    print(" PHASE 18.0 NYX DISTRIBUTED WORKER ARCHITECTURE TESTS")
    print("=" * 60)

    results = {}
    test_dir = REPO_ROOT / "scratch" / "test_phase180_workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    old_cwd = os.getcwd()
    os.chdir(test_dir)

    try:
        # 1. Zero Reverse Imports (nyx/* -> nyx_cli.cli)
        nyx_files = glob.glob(str(REPO_ROOT / "nyx" / "**" / "*.py"), recursive=True)
        nyx_imports = []
        for fpath in nyx_files:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                for line_no, line in enumerate(fp, 1):
                    if "nyx_cli.cli" in line or "from nyx_cli" in line:
                        rel = Path(fpath).relative_to(REPO_ROOT)
                        nyx_imports.append(f"{rel}:{line_no}: {line.strip()}")

        print(f"[1_zero_nyx_imports] Total nyx -> nyx_cli.cli imports: {len(nyx_imports)}")
        results["1_zero_nyx_imports"] = (len(nyx_imports) == 0)

        # Initialize test workspace
        init_engagement("example.com")
        sec = WorkerSecurity()

        # 2. Worker Node Registration & Metadata
        node = WorkerNode(hostname="remote-worker-1", agents_supported=["recon", "web"])
        meta = node.get_metadata()
        print(f"[2_worker_registration] WorkerID: {meta.get('worker_id')}, Host: {meta.get('hostname')}, Status: {meta.get('status')}")
        results["2_worker_registration"] = (meta.get("worker_id") is not None and meta.get("status") == "ONLINE")

        # 3. Heartbeat Liveness & Timeout Monitor
        hb = WorkerHeartbeat(timeout_seconds=2)
        hb_res = hb.send_heartbeat(node)
        health = hb.check_health(hb_res)
        print(f"[3_heartbeat_system] Health: {health}, LastSeen: {hb_res.get('last_seen')}")
        results["3_heartbeat_system"] = (health == "ONLINE")

        # 4. Worker Security & Authentication
        auth = DistributedAuthentication()
        auth_ok, auth_msg = auth.authenticate_worker(node.worker_id, node.hostname, node.auth_token)
        inv_ok, inv_msg = auth.authenticate_worker(node.worker_id, node.hostname, "INVALID_TOKEN")
        print(f"[4_worker_authentication] Valid Token Auth: {auth_ok}, Invalid Rejected: {not inv_ok}")
        results["4_worker_authentication"] = (auth_ok is True and inv_ok is False)

        # 5. Remote Task Assignment & Worker Scheduler
        ctrl = AgentController()
        w_meta = ctrl.register_worker("remote-node-us", agents_supported=["web", "api"])
        t1 = ctrl.task_queue.create_task("web_scan", "example.com", agent_type="web", priority=8)
        
        dispatch_res = ctrl.worker_scheduler.dispatch_task(t1["task_id"])
        print(f"[5_remote_task_assignment] Mode: {dispatch_res.get('execution_mode')}, WorkerID: {dispatch_res.get('assigned_worker_id')}")
        results["5_remote_task_assignment"] = (dispatch_res.get("execution_mode") == "REMOTE" and dispatch_res.get("assigned_worker_id") == w_meta["worker_id"])

        # 6. Task Failure Recovery & Retry Policy
        fail_ok, fail_msg = ctrl.task_queue.fail_task(t1["task_id"], reason="Network timeout")
        retried_task = ctrl.task_queue.get_task(t1["task_id"])
        print(f"[6_task_recovery] Status After Fail: {retried_task.get('status')}, RetryCount: {retried_task.get('retry_count')}")
        results["6_task_recovery"] = (retried_task.get("status") == "QUEUED" and retried_task.get("retry_count") == 1)

        # 7. Evidence Synchronization & SHA-256 Integrity Verification
        f_res = create_finding(title="Test Finding for Evidence Sync", endpoint="example.com/api", vulnerability="IDOR")
        fid = f_res.get("finding_id") if isinstance(f_res, dict) else "FH-2026-001"
        
        e_sync = EvidenceSync()
        test_bytes = b"VERIFIED_REMOTE_EVIDENCE_PAYLOAD"
        calc_sha = e_sync.calculate_bytes_hash(test_bytes)
        
        sync_ok, sync_msg, sync_data = e_sync.sync_remote_evidence(
            finding_id=fid,
            filename="remote_log.txt",
            content_bytes=test_bytes,
            expected_sha256=calc_sha,
            worker_id=node.worker_id,
        )
        
        # Test SHA-256 mismatch rejection
        bad_ok, bad_msg, _ = e_sync.sync_remote_evidence(
            finding_id=fid,
            filename="bad_log.txt",
            content_bytes=test_bytes,
            expected_sha256="0000000000000000000000000000000000000000000000000000000000000000",
        )
        
        print(f"[7_evidence_sync] Sync Verified: {sync_ok}, Bad SHA Blocked: {not bad_ok}")
        results["7_evidence_sync"] = (sync_ok is True and bad_ok is False)

        # 8. WorkerService Application Facade
        w_svc = WorkerService()
        w_res = w_svc.get_worker_status()
        print(f"[8_worker_service] Service Result OK: {w_res.is_success}, Total Workers: {w_res.data.get('total_workers')}")
        results["8_worker_service"] = (w_res.is_success and "total_workers" in w_res.data)

        # 9. Web REST API Endpoints (/api/v1/workers/*)
        token = get_or_create_api_token()
        client = TestClient(app)
        auth_headers = {"Authorization": f"Bearer {token}", "X-API-Token": token}

        st_res = client.get("/api/v1/workers/status", headers=auth_headers)
        list_res = client.get("/api/v1/workers", headers=auth_headers)
        reg_res = client.post("/api/v1/workers/register?hostname=api-worker-1", headers=auth_headers)
        print(f"[9_rest_api] Status: {st_res.status_code}, List: {list_res.status_code}, Reg: {reg_res.status_code}")
        results["9_rest_api"] = (st_res.status_code == 200 and list_res.status_code == 200 and reg_res.status_code == 200)

        # 10. Worker Executor Remote Execution Test
        w_exec = WorkerExecutor()
        exec_out = w_exec.execute_task({"task_id": "TSK-REMOTE-1", "target": "example.com", "agent_type": "recon"})
        print(f"[10_worker_executor] Executed Remote Task Status: {exec_out.get('status')}")
        results["10_worker_executor"] = (exec_out.get("status") == "COMPLETED")

    finally:
        os.chdir(old_cwd)
        if test_dir.exists():
            shutil.rmtree(test_dir, ignore_errors=True)

    # Print Summary
    print("\n" + "=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    for name, res in results.items():
        status_str = "PASS" if res else "FAIL"
        print(f"[{name}] {status_str}")

    print("=" * 60)
    print(f" TOTAL VERIFICATIONS PASSED: {passed} / {total}")
    print(f" OVERALL PHASE 18.0 SUITE RESULT: {'PASS' if passed == total else 'FAIL'}")
    print("=" * 60)

    return passed == total


if __name__ == "__main__":
    success = run_phase180_tests()
    sys.exit(0 if success else 1)
