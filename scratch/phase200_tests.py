"""
Phase 20 Verification Suite — NYX Continuous Security Intelligence & Monitoring Platform
Tests:
1. Asset history snapshotting (AssetGraph & AssetHistory)
2. Change detection engine (DiffEngine & ChangeDetector)
3. Monitoring scheduler & jobs (MonitoringScheduler & SurfaceWatcher)
4. Alert generation & providers (AlertManager & AlertEvents)
5. Research recommendations engine (OpportunityEngine & PriorityRanker)
6. Knowledge backup (KnowledgeProtection.create_backup)
7. Knowledge verification (KnowledgeProtection.verify_integrity)
8. Dashboard REST API endpoints (/api/v1/continuous/*)
9. Agent integration facade (ContinuousService)
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

from nyx.intelligence import AssetGraph, AssetHistory, DiffEngine, AssetTracker, ChangeDetector
from nyx.monitor import MonitoringJob, MonitoringScheduler, SurfaceWatcher, MonitoringAlerts
from nyx.alerts import AlertEvents, AlertProviders, AlertManager
from nyx.research import PriorityRanker, OpportunityEngine
from nyx.knowledge import KnowledgeProtection
from nyx.application.continuous_service import ContinuousService
from nyx.web.app import app
from nyx.web.auth import get_or_create_api_token
from nyx.core.engagement import init_engagement


def run_phase200_tests():
    print("=" * 60)
    print(" PHASE 20.0 NYX CONTINUOUS SECURITY INTELLIGENCE TESTS")
    print("=" * 60)

    results = {}
    test_dir = REPO_ROOT / "scratch" / "test_phase200_workspace"
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

        # 2. Asset History & Snapshotting
        ag1 = AssetGraph(target="example.com")
        ag1.add_subdomain("api.example.com")
        ag1.add_endpoint("/api/v1/users", "GET", ["id"])
        
        history = AssetHistory()
        snap1 = history.record_snapshot(ag1)
        snaps = history.get_snapshots("example.com")
        print(f"[2_asset_history] Snapshot Count: {len(snaps)}, Target: {snaps[0].get('target')}")
        results["2_asset_history"] = (len(snaps) >= 1 and snaps[0].get("target") == "example.com")

        # 3. Change Detection & Diff Engine
        ag2 = AssetGraph.from_dict(ag1.to_dict())
        ag2.add_endpoint("/api/v2/graphql", "POST", ["query"])
        diff = DiffEngine.compare_graphs(ag1, ag2)
        
        cd = ChangeDetector()
        events = cd.analyze_diff(diff)
        print(f"[3_change_detection] Has Changes: {diff.get('has_changes')}, Events Detected: {len(events)}")
        results["3_change_detection"] = (diff.get("has_changes") is True and len(events) >= 1)

        # 4. Monitoring Scheduler & Surface Watcher
        m_sched = MonitoringScheduler()
        m_job = m_sched.create_job("recon_refresh", "example.com")
        run_res = m_sched.run_job(m_job.job_id)
        print(f"[4_monitoring_scheduler] Job ID: {m_job.job_id}, Run Status: {run_res.get('job', {}).get('status')}")
        results["4_monitoring_scheduler"] = (run_res.get("job", {}).get("status") == "COMPLETED")

        # 5. Alert System & Alert Manager
        am = AlertManager()
        alt = am.raise_alert("example.com", "New GraphQL Endpoint Exposed", "HIGH", "Detected /api/v2/graphql")
        alerts_list = am.list_alerts("example.com")
        print(f"[5_alert_system] Raised AlertID: {alt.get('alert_id')}, Total Alerts: {len(alerts_list)}")
        results["5_alert_system"] = (alt.get("alert_id") is not None and len(alerts_list) == 1)

        # 6. Research Opportunity Engine & Skill Mapping
        opp_eng = OpportunityEngine()
        evt = {"target": "example.com", "event_type": "NEW_ENDPOINT", "severity": "HIGH", "description": "New GraphQL API detected"}
        opp = opp_eng.analyze_event(evt)
        opps = opp_eng.list_opportunities("example.com")
        print(f"[6_research_opportunities] Opp ID: {opp.get('opportunity_id')}, Recommended Skills: {opp.get('recommended_skills')}")
        results["6_research_opportunities"] = (opp.get("opportunity_id") is not None and "hunt-graphql" in opp.get("recommended_skills", []))

        # 7. Knowledge Backup
        kp = KnowledgeProtection(base_dir=REPO_ROOT)
        backup_res = kp.create_backup()
        print(f"[7_knowledge_backup] Backup File: {backup_res.get('backup_file')}, Files Backed Up: {backup_res.get('files_count')}")
        results["7_knowledge_backup"] = (backup_res.get("success") is True and backup_res.get("files_count") > 0)

        # 8. Knowledge Verification
        verify_res = kp.verify_integrity()
        print(f"[8_knowledge_verification] Intact: {verify_res.get('intact')}, Total Skills: {verify_res.get('total_skills_count')}")
        results["8_knowledge_verification"] = (verify_res.get("intact") is True and verify_res.get("total_skills_count") > 0)

        # 9. Dashboard REST API Endpoints (/api/v1/continuous/*)
        token = get_or_create_api_token()
        client = TestClient(app)
        auth_headers = {"Authorization": f"Bearer {token}", "X-API-Token": token}

        st_res = client.post("/api/v1/continuous/monitor/start?target=example.com", headers=auth_headers)
        stat_res = client.get("/api/v1/continuous/monitor/status", headers=auth_headers)
        his_res = client.get("/api/v1/continuous/assets/history", headers=auth_headers)
        chg_res = client.get("/api/v1/continuous/changes", headers=auth_headers)
        alt_res = client.get("/api/v1/continuous/alerts", headers=auth_headers)
        opp_res = client.get("/api/v1/continuous/research/opportunities", headers=auth_headers)
        ver_res = client.get("/api/v1/continuous/knowledge/verify", headers=auth_headers)
        
        print(f"[9_dashboard_api] Start: {st_res.status_code}, Status: {stat_res.status_code}, History: {his_res.status_code}, Changes: {chg_res.status_code}, Alerts: {alt_res.status_code}, Opps: {opp_res.status_code}, Verify: {ver_res.status_code}")
        results["9_dashboard_api"] = (st_res.status_code == 200 and stat_res.status_code == 200 and his_res.status_code == 200 and chg_res.status_code == 200 and alt_res.status_code == 200 and opp_res.status_code == 200 and ver_res.status_code == 200)

        # 10. Application ContinuousService Integration
        c_svc = ContinuousService()
        svc_res = c_svc.get_monitoring_status()
        print(f"[10_continuous_service] Service Result Success: {svc_res.is_success}")
        results["10_continuous_service"] = (svc_res.is_success is True)

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
    print(f" OVERALL PHASE 20.0 SUITE RESULT: {'PASS' if passed == total else 'FAIL'}")
    print("=" * 60)

    return passed == total


if __name__ == "__main__":
    success = run_phase200_tests()
    sys.exit(0 if success else 1)
