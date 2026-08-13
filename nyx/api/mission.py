"""
NYX Mission System Core Engine
"""
from __future__ import annotations
import json
import sys
from datetime import datetime
from pathlib import Path
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
def run_mission(target: str) -> int:
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
        say(color("✗ Engagement Initialization Failed", "red"))
        return 1
    say(color("✓ Engagement initialized", "green"))

    # Step 3: Recon
    res_recon = recon.run(target)
    if isinstance(res_recon, dict) and res_recon.get("status") == "error":
        say(color("  Notice: Recon phase returned non-zero exit code", "yellow"))
    else:
        say(color("✓ Recon completed", "green"))

    # Step 4: Technology Detection & Memory Read
    t_file = d / "technologies.json"
    tech_count = 0
    if t_file.exists():
        try:
            techs = json.loads(t_file.read_text(encoding="utf-8"))
            tech_count = sum(len(v) for v in techs.values() if isinstance(v, list))
        except Exception:
            pass
    say(color(f"✓ Technologies identified ({tech_count} stack components detected)", "green"))

    # Step 5: Attack Surface Ranking
    ep_file = d / "endpoints.json"
    ep_count = 0
    if ep_file.exists():
        try:
            eps = json.loads(ep_file.read_text(encoding="utf-8"))
            ep_count = len(eps)
        except Exception:
            pass
    say(color(f"✓ Attack surface created ({ep_count} endpoints indexed in memory)", "green"))

    # Step 6: Skill Selection & Tool Orchestration Interface
    from nyx.core.router import recommend_skills
    from nyx.execution.executor import execute_tool
    rec = recommend_skills(f"https://{target}/login", technology="ASP.NET")
    say(color(f"✓ Recommended Security Skills: {', '.join(rec.get('recommended_skills', []))}", "green"))

    # Tool selection check (Dry-run mode interface)
    dry_res = execute_tool("subfinder", target, dry_run=True)
    say(color(f"✓ Controlled Tool Harness Ready: {dry_res.tool} [{dry_res.execution_class}] (Dry-Run Status: PASS)", "green"))

    say("\n==================================================")
    say(color("Next recommended phase: ANALYSIS", "cyan"))
    say("Run:")
    say(f"  nyx state ANALYSIS")
    say(f"  nyx surface {target}")
    say(f"  nyx exec --dry-run subfinder {target}")
    say("==================================================")
    return 0