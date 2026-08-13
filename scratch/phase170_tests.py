"""
Phase 17 Verification Suite — NYX Multi-Agent Distributed Research Architecture
Tests:
1. Agent Controller creation (AgentController)
2. Specialized Agent registration (ReconAgent, WebAgent, APIAgent, etc.)
3. Multiple Agents coexistence & Registry isolation
4. Distributed Task Queue creation & priority scheduling
5. Agent Message Bus event publishing & persistent storage
6. Specialized Agent lifecycle & output schemas
7. Human Approval enforcement
8. REST API endpoints (/api/v1/fleet/*)
9. Fleet Application Service facade
10. Zero reverse nyx_cli.cli imports in nyx/* and nyx/agents/*
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import sys

from pathlib import Path
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nyx.agent.manager import AgentController, AgentRegistry, DistributedScheduler
from nyx.agent.bus import AgentMessageBus
from nyx.agent.tasks import DistributedTaskQueue
from nyx.agents import (
    ReconAgent,
    WebAgent,
    APIAgent,
    TechnologyAgent,
    ValidationAgent,
    ReportingAgent,
)
from nyx.application.fleet_service import FleetService
from nyx.web.app import app
from nyx.web.auth import get_or_create_api_token
from nyx.core.engagement import init_engagement


def run_phase170_tests():
    print("=" * 60)
    print(" PHASE 17.0 NYX MULTI-AGENT DISTRIBUTED ARCHITECTURE TESTS")
    print("=" * 60)

    results = {}
    test_dir = REPO_ROOT / "scratch" / "test_phase170_workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    old_cwd = os.getcwd()
    os.chdir(test_dir)

    try:
        # 1. Zero Reverse Imports (nyx/* & nyx/agents/* -> nyx_cli.cli)
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

        # Initialize workspace & controller
        init_engagement("example.com")
        ctrl = AgentController()

        # 2. Agent Controller & Specialized Agent Creation
        recon_info = ctrl.create_agent("recon", "example.com")
        web_info = ctrl.create_agent("web", "example.com")
        api_info = ctrl.create_agent("api", "example.com")
        print(f"[2_agent_creation] Created: Recon ({recon_info['agent_id']}), Web ({web_info['agent_id']}), API ({api_info['agent_id']})")
        results["2_agent_creation"] = (len(ctrl.list_agents()) == 3)

        # 3. Multiple Agents Coexistence & Registry Isolation
        recon_agents = ctrl.list_agents(agent_type="recon")
        web_agents = ctrl.list_agents(agent_type="web")
        print(f"[3_registry_isolation] Recon Count: {len(recon_agents)}, Web Count: {len(web_agents)}")
        results["3_registry_isolation"] = (len(recon_agents) == 1 and len(web_agents) == 1)

        # 4. Distributed Task Queue & Priority Scheduling
        t1 = ctrl.task_queue.create_task("passive_recon", "example.com", agent_type="recon", priority=10)
        t2 = ctrl.task_queue.create_task("web_scan", "example.com", agent_type="web", priority=3)
        ctrl.task_queue.update_task_status(t1["task_id"], "QUEUED")

        scheduled = ctrl.scheduler.schedule_next_task()
        print(f"[4_task_queue] Scheduled TaskID: {scheduled.get('task_id') if scheduled else None}, Priority: {scheduled.get('priority') if scheduled else None}")
        results["4_task_queue"] = (scheduled is not None and scheduled.get("task_id") == t1["task_id"])

        # 5. Message Bus Events & Storage Persistence
        bus = AgentMessageBus()
        ev = bus.publish("ReconAgent", "WebAgent", "recon_completed", {"found_endpoints": 5})
        history = bus.get_history(event_type="recon_completed")
        print(f"[5_message_bus] Events Recorded: {len(history)}, Sender: {ev.get('sender')}")
        results["5_message_bus"] = (len(history) >= 1 and history[0].get("sender") == "ReconAgent")

        # 6. Specialized Agent Execution Output Schema
        recon_ag = ReconAgent("example.com")
        out = recon_ag.execute_specialized_task({})
        print(f"[6_agent_output_schema] AgentType: {out.get('agent_type')}, Assets: {len(out.get('assets', []))}")
        results["6_agent_output_schema"] = (out.get("agent_type") == "recon" and len(out.get("assets", [])) > 0)

        # 7. Approval Enforcement Across Agents
        prop = recon_ag.inner_agent.propose_action("Propose active scan", "Testing scope", tool_name="nmap")
        act_id = prop.get("action_id")
        block_exec = recon_ag.inner_agent.execute(act_id)
        print(f"[7_approval_enforcement] Unapproved Exec Blocked: {block_exec.get('policy_blocked')}")
        results["7_approval_enforcement"] = (block_exec.get("policy_blocked") is True)

        # 8. Fleet Application Service Facade
        svc = FleetService()
        f_stat = svc.get_fleet_status()
        print(f"[8_fleet_service] Status Returned, Total Tasks: {f_stat.data.get('total_tasks')}")
        results["8_fleet_service"] = (f_stat.is_success and "total_agents" in f_stat.data)

        # 9. Web REST API (/api/v1/fleet/*)
        token = get_or_create_api_token()
        client = TestClient(app)
        auth_headers = {"Authorization": f"Bearer {token}", "X-API-Token": token}

        st_res = client.get("/api/v1/fleet/status", headers=auth_headers)
        ag_res = client.get("/api/v1/fleet/agents", headers=auth_headers)
        ts_res = client.get("/api/v1/fleet/tasks", headers=auth_headers)
        print(f"[9_rest_api] Fleet Status: {st_res.status_code}, Agents: {ag_res.status_code}, Tasks: {ts_res.status_code}")
        results["9_rest_api"] = (st_res.status_code == 200 and ag_res.status_code == 200 and ts_res.status_code == 200)

        # 10. Agent Stopping & Lifecycle Removal
        stop_res = ctrl.stop_agent(recon_info["agent_id"])
        print(f"[10_agent_lifecycle] Agent Stopped: {stop_res}, Remaining Agents: {len(ctrl.list_agents())}")
        results["10_agent_lifecycle"] = (stop_res is True and len(ctrl.list_agents()) == 2)

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
    print(f" OVERALL PHASE 17.0 SUITE RESULT: {'PASS' if passed == total else 'FAIL'}")
    print("=" * 60)

    return passed == total


if __name__ == "__main__":
    success = run_phase170_tests()
    sys.exit(0 if success else 1)
