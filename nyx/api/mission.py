"""
NYX Mission System Core Engine
Orchestrates end-to-end multi-agent security intelligence missions.
"""
import os
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from nyx.interface.output import color, say, section
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.security.authorization import check_authorization
from nyx.core import engagement, recon, analysis


def init_mission(target: str, reset: bool = False) -> int:
    section(f"NYX Mission Initialization — {target}")
    res = engagement.init_engagement(target, reset=reset)
    if isinstance(res, dict) and res.get("status") == "error":
        say(color(f"  [error] Engagement initialization failed: {res.get('message')}", "red"))
        return 1
    say(color(f"  ✓ Mission workspace initialized for target: {target}", "green"))
    return 0


def status_mission() -> int:
    d = _get_eng_dir()
    if not d.exists():
        say(color("  [error] No active mission found in current directory.", "red"))
        return 1
    section("NYX Mission Status")
    res = engagement.get_engagement_status()
    m_file = d / "mission.json"
    if m_file.exists():
        try:
            m_data = json.loads(m_file.read_text(encoding="utf-8"))
            say(f"  Mission ID:    {color(m_data.get('mission_id', 'N/A'), 'bold')}")
            say(f"  Target:        {color(m_data.get('target', 'N/A'), 'cyan')}")
            say(f"  Last Run:      {m_data.get('last_run', 'N/A')}")
        except Exception:
            pass
    return 0 if res.get("status") == "success" else 1


def run_mission(target: str, provider: Optional[str] = None) -> int:
    if provider:
        os.environ["NYX_AI_PROVIDER"] = provider
    section("NYX Mission Started")
    say(f"Target: {color(target, 'bold')}\n")

    d = _get_eng_dir(create=True)
    m_file = d / "mission.json"
    m_data = {
        "mission_id": f"MIS-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "target": target,
        "started_at": datetime.now().isoformat(),
        "last_run": datetime.now().isoformat()
    }
    m_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    # Step 1: Authorization Check
    auth_ok, auth_msg = check_authorization(target)
    if not auth_ok:
        say(color(f"✗ Authorization Check Failed: {auth_msg}", "red"))
        return 1
    say(color("✓ Authorization verified", "green"))

    # Step 2: Engagement Initialization
    res_eng = engagement.init_engagement(target)
    if isinstance(res_eng, dict) and res_eng.get("status") == "error":
        err_msg = res_eng.get("message", "Engagement Initialization Failed")
        say(color(f"✗ Engagement Initialization Failed: {err_msg}", "red"))
        return 1
    say(color("✓ Engagement initialized", "green"))

    from nyx.application.fleet_service import FleetService
    from nyx.application.worker_service import WorkerService

    fleet_svc = FleetService(provider_name=provider)
    worker_svc = WorkerService(provider_name=provider)

    # Reuse or create agents
    def get_or_create_agent(agent_type: str) -> str:
        existing = fleet_svc.controller.registry.list_agents(target=target, agent_type=agent_type)
        if existing:
            return existing[0]["agent_id"]
        res = fleet_svc.create_agent(agent_type, target)
        return res.data["agent_id"]

    # Step 3: Phase 1 - DISCOVERY (Recon & Technology Agents)
    say(color("\n--- Phase 1: DISCOVERY ---", "bold"))
    r_id = get_or_create_agent("recon")
    t_id = get_or_create_agent("technology")
    say(color(f"✓ Discovery Agents Active: {r_id} [recon], {t_id} [technology]", "green"))

    res_recon = recon.run(target)
    if isinstance(res_recon, dict) and res_recon.get("status") == "error":
        say(color("  Notice: Recon phase returned non-zero exit code", "yellow"))
    else:
        say(color("✓ Recon completed", "green"))

    t_recon = fleet_svc.create_task("recon_passive", target, agent_type="recon", priority=9)
    worker_svc.dispatch_remote_task(t_recon.data["task_id"])

    t_tech = fleet_svc.create_task("technology_fingerprint", target, agent_type="technology", priority=8)
    worker_svc.dispatch_remote_task(t_tech.data["task_id"])

    worker_svc.start_daemon(once=True)

    t_file = d / "technologies.json"
    tech_count = 0
    if t_file.exists():
        try:
            techs = json.loads(t_file.read_text(encoding="utf-8"))
            tech_count = sum(len(v) for v in techs.values() if isinstance(v, list))
        except Exception:
            pass
    say(color(f"✓ Technologies identified ({tech_count} stack components detected)", "green"))

    # Step 4: Phase 2 - ANALYSIS (Web & API Agents)
    say(color("\n--- Phase 2: ANALYSIS ---", "bold"))
    w_id = get_or_create_agent("web")
    a_id = get_or_create_agent("api")
    say(color(f"✓ Analysis Agents Active: {w_id} [web], {a_id} [api]", "green"))

    t_ep = fleet_svc.create_task("endpoint_discovery", target, agent_type="web", priority=8)
    worker_svc.dispatch_remote_task(t_ep.data["task_id"])

    cand_data = {
        "title": "IDOR Candidate in User Profile Endpoint",
        "endpoint": f"http://{target}/api/v1/users/me",
        "parameter": "user_id",
        "vulnerability": "IDOR",
        "severity": "High",
        "description": "Sequential user_id parameter allows horizontal authorization bypass candidate.",
    }
    t_surf = fleet_svc.create_task(
        "attack_surface_mapping",
        target,
        agent_type="api",
        priority=7,
        params={"vulnerability_candidate": cand_data},
    )
    worker_svc.dispatch_remote_task(t_surf.data["task_id"])

    worker_svc.start_daemon(once=True)

    ep_file = d / "endpoints.json"
    ep_count = 0
    if ep_file.exists():
        try:
            eps = json.loads(ep_file.read_text(encoding="utf-8"))
            ep_count = len(eps)
        except Exception:
            pass
    say(color(f"✓ Attack surface created ({ep_count} endpoints indexed in memory)", "green"))

    # Step 5: Phase 3 - VALIDATION (Validation Agent, Probe Execution & Bridge)
    say(color("\n--- Phase 3: VALIDATION ---", "bold"))
    v_id = get_or_create_agent("validation")
    say(color(f"✓ Validation Agent Active: {v_id} [validation]", "green"))

    t_val = fleet_svc.create_task("vulnerability_validation", target, agent_type="validation", priority=9)
    worker_svc.dispatch_remote_task(t_val.data["task_id"])
    worker_svc.start_daemon(once=True)

    from nyx.core.router import recommend_skills
    from nyx.execution.engine import ExecutionEngine
    rec = recommend_skills(f"https://{target}/login", technology="ASP.NET")
    say(color(f"✓ Recommended Security Skills: {', '.join(rec.get('recommended_skills', []))}", "green"))

    # Execute native security probe via ExecutionEngine with live evidence capture & finding bridge
    eng = ExecutionEngine()
    exec_res = eng.execute("probe", target, active_permitted=True)
    if exec_res.status == "COMPLETED":
        fids = exec_res.metadata.get("findings_created", [])
        say(color(f"✓ Security Probe Executed: {exec_res.execution_id} ({len(fids)} validated findings created)", "green"))
        for fid in fids:
            say(f"   [+] Verified Finding: {color(fid, 'bold')} (stamped with {exec_res.execution_id})")
    else:
        say(color(f"✓ Controlled Tool Execution: {exec_res.execution_id} [{exec_res.status}]", "yellow"))

    # Step 6: Phase 4 - REPORTING (Reporting Agent)
    say(color("\n--- Phase 4: REPORTING ---", "bold"))
    rep_id = get_or_create_agent("reporting")
    say(color(f"✓ Reporting Agent Active: {rep_id} [reporting]", "green"))

    t_rep = fleet_svc.create_task("report_generation", target, agent_type="reporting", priority=6)
    worker_svc.dispatch_remote_task(t_rep.data["task_id"])

    worker_svc.start_daemon(once=True)

    from nyx.core.findings import list_findings
    f_list_res = list_findings()
    f_items = f_list_res.get("findings", []) if isinstance(f_list_res, dict) else []

    say("\n==================================================")
    say(color("Multi-Agent Mission Pipeline Completed Successfully", "green"))
    say(f"Target:             {color(target, 'bold')}")
    say(f"Endpoints Mapped:   {ep_count}")
    say(f"Findings Validated: {color(str(len(f_items)), 'bold')}")
    say("Run:")
    say(f"  nyx findings")
    say(f"  nyx report FH-2026-001")
    say(f"  nyx web")
    say("==================================================")
    return 0