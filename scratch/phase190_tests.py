"""
Phase 19 Verification Suite — NYX Dynamic Security Testing & Browser Intelligence Engine
Tests:
1. Browser session creation (BrowserSession & BrowserContext)
2. Playwright abstraction (BrowserController)
3. Runtime event capture (BrowserEvents & RequestLogger)
4. Authentication storage (SessionManager & AuthProviders)
5. Dynamic agent creation (DynamicAgent)
6. Approval enforcement (BrowserExecutor)
7. Evidence capture (BrowserExecutor)
8. Dashboard API (/api/v1/browser/*)
9. Worker compatibility (DynamicAgent registration)
10. Zero reverse nyx_cli.cli imports in nyx/*
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

from nyx.browser import BrowserSession, BrowserContext, BrowserController, BrowserEvents, BrowserStorage
from nyx.runtime import RequestLogger, NetworkObserver, JSObserver, DOMObserver
from nyx.auth import SessionManager, AuthFlows, AuthProviders
from nyx.agents import DynamicAgent
from nyx.execution import BrowserExecutor
from nyx.application.browser_service import BrowserService
from nyx.agent.approval import ApprovalSystem
from nyx.web.app import app
from nyx.web.auth import get_or_create_api_token
from nyx.core.engagement import init_engagement
from nyx.core.findings import create_finding


def run_phase190_tests():
    print("=" * 60)
    print(" PHASE 19.0 NYX DYNAMIC TESTING & BROWSER INTELLIGENCE TESTS")
    print("=" * 60)

    results = {}
    test_dir = REPO_ROOT / "scratch" / "test_phase190_workspace"
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

        # Initialize workspace
        init_engagement("example.com")

        # 2. Browser Session Creation & Context
        ctx = BrowserContext(target="example.com")
        sess = BrowserSession(context=ctx)
        nav = sess.navigate("https://example.com/login")
        print(f"[2_browser_session] SessionID: {ctx.session_id}, Status: {nav.get('status')}")
        results["2_browser_session"] = (ctx.session_id is not None and nav.get("status") == "success")

        # 3. Playwright Abstraction Controller
        ctrl = BrowserController()
        s1 = ctrl.create_session("example.com")
        stored_sessions = ctrl.list_sessions()
        print(f"[3_browser_controller] SessionID: {s1.context.session_id}, Stored Count: {len(stored_sessions)}")
        results["3_browser_controller"] = (len(stored_sessions) >= 1)

        # 4. Runtime Event Capture & Intelligence Graph
        dom_obs = DOMObserver()
        dom_obs.network.observe("GET", "https://example.com/api/v1/user", {"User-Agent": "Test"})
        dom_obs.record_form("/api/login", "POST", ["username", "password"])
        graph = dom_obs.get_runtime_intelligence_graph()
        print(f"[4_runtime_capture] Requests: {len(graph.get('requests', []))}, APIs: {len(graph.get('apis', []))}")
        results["4_runtime_capture"] = (len(graph.get("requests", [])) == 1 and len(graph.get("apis", [])) == 1)

        # 5. Authentication Storage & Session Manager
        sm = SessionManager()
        reg_sess = sm.register_session("SESS-123", "example.com", "eyJhbGciOiJIUzI1NiJ9.test")
        flow_rec = sm.flows.record_step("login_flow", "form", "submit", {"url": "https://example.com/login"})
        print(f"[5_authentication_storage] Session Reg: {reg_sess.get('session_id')}, Flow Steps: {len(sm.flows.get_flow('login_flow'))}")
        results["5_authentication_storage"] = (reg_sess.get("session_id") == "SESS-123" and len(sm.flows.get_flow("login_flow")) == 1)

        # 6. Dynamic Agent Creation & Process Task
        dyn_agent = DynamicAgent(target="example.com")
        task_out = dyn_agent.process_task({"task_id": "TSK-DYN-1", "params": {"url": "https://example.com"}})
        print(f"[6_dynamic_agent] AgentType: {dyn_agent.agent_type}, Output Target: {task_out.get('target')}")
        results["6_dynamic_agent"] = (dyn_agent.agent_type == "dynamic" and task_out.get("target") == "example.com")

        # 7. Approval Enforcement in BrowserExecutor
        app_sys = ApprovalSystem()
        aid = app_sys.submit_for_approval({
            "action_id": "ACT-BROWSER-1",
            "tool": "playwright",
            "command": "playwright navigate https://example.com",
            "args": ["https://example.com"],
            "reason": "Dynamic test",
            "target": "example.com",
        })
        
        executor = BrowserExecutor(approval_system=app_sys)
        # Execution before approval -> should fail
        unapp_res = executor.execute_approved_browser_action(aid, "navigate", "example.com", {"url": "https://example.com"})
        
        # Approve and execute
        app_sys.approve_action(aid)
        app_res = executor.execute_approved_browser_action(aid, "navigate", "example.com", {"url": "https://example.com"})
        
        print(f"[7_approval_enforcement] Unapproved Blocked: {not unapp_res.get('success')}, Approved Succeeded: {app_res.get('success')}")
        results["7_approval_enforcement"] = (unapp_res.get("success") is False and app_res.get("success") is True)

        # 8. Evidence Capture in BrowserExecutor
        f_res = create_finding(title="Test Dynamic Finding", endpoint="example.com/api", vulnerability="XSS")
        fid = f_res.get("finding_id") if isinstance(f_res, dict) else "FH-2026-001"
        
        aid2 = app_sys.submit_for_approval({
            "action_id": "ACT-BROWSER-2",
            "tool": "playwright",
            "command": "playwright screenshot",
            "args": [],
            "reason": "Screenshot test",
            "target": "example.com",
        })
        app_sys.approve_action(aid2)
        
        ev_exec_res = executor.execute_approved_browser_action(aid2, "screenshot", "example.com", finding_id=fid)
        print(f"[8_evidence_capture] Exec Success: {ev_exec_res.get('success')}, Evidence Attached: {ev_exec_res.get('evidence') is not None}")
        results["8_evidence_capture"] = (ev_exec_res.get("success") is True and ev_exec_res.get("evidence") is not None)

        # 9. Dashboard REST API Endpoints (/api/v1/browser/*)
        token = get_or_create_api_token()
        client = TestClient(app)
        auth_headers = {"Authorization": f"Bearer {token}", "X-API-Token": token}

        st_res = client.post("/api/v1/browser/start?target=example.com", headers=auth_headers)
        ls_res = client.get("/api/v1/browser/sessions", headers=auth_headers)
        rt_res = client.get("/api/v1/browser/runtime", headers=auth_headers)
        fl_res = client.get("/api/v1/browser/auth/flows", headers=auth_headers)
        ag_res = client.post("/api/v1/browser/agent/dynamic?target=example.com", headers=auth_headers)
        
        print(f"[9_dashboard_api] Start: {st_res.status_code}, Sessions: {ls_res.status_code}, Runtime: {rt_res.status_code}, Auth: {fl_res.status_code}, Agent: {ag_res.status_code}")
        results["9_dashboard_api"] = (st_res.status_code == 200 and ls_res.status_code == 200 and rt_res.status_code == 200 and fl_res.status_code == 200 and ag_res.status_code == 200)

        # 10. Worker Compatibility Facade Integration
        b_svc = BrowserService()
        dyn_res = b_svc.run_dynamic_agent("example.com")
        print(f"[10_worker_compatibility] Service Success: {dyn_res.is_success}")
        results["10_worker_compatibility"] = (dyn_res.is_success is True)

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
    print(f" OVERALL PHASE 19.0 SUITE RESULT: {'PASS' if passed == total else 'FAIL'}")
    print("=" * 60)

    return passed == total


if __name__ == "__main__":
    success = run_phase190_tests()
    sys.exit(0 if success else 1)
