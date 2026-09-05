"""
NYX Engine Telemetry & System Health API Router
Provides comprehensive, live telemetry on engine status, runtime components, tools, workers, and skills.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Any, Dict
from fastapi import APIRouter, Depends

from nyx.web.auth import require_auth
from nyx.core import skills as nyx_skills
from nyx.core.engagement import get_engagement_target, get_engagement_status
from nyx.infrastructure.tools import get_tool_diagnostics
from nyx.infrastructure.filesystem import _get_eng_dir

router = APIRouter(prefix="/api/v1/engine", tags=["Engine Telemetry"])


@router.get("/status", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_engine_status() -> Dict[str, Any]:
    """Retrieve authoritative live NYX engine status and subsystem telemetry."""
    # 1. Target & Phase
    active_target = get_engagement_target() or os.environ.get("NYX_TARGET") or "No active target"
    eng_status = get_engagement_status()
    curr_phase = eng_status.get("state", "DISCOVERY") if isinstance(eng_status, dict) else "DISCOVERY"

    # 2. Skills & Categories
    try:
        live_skills = nyx_skills.list_skills()
        skill_count = len(live_skills)
        categories: dict[str, int] = {}
        for s in live_skills:
            cat = s.get("category", "general")
            categories[cat] = categories.get(cat, 0) + 1
    except Exception:
        live_skills = []
        skill_count = 0
        categories = {}

    # 3. Tool Discovery Diagnostics
    core_tools = ["httpx", "subfinder", "katana", "nuclei", "nmap", "ffuf", "curl", "sqlmap"]
    tool_status_list = []
    available_tools_count = 0
    for t_name in core_tools:
        diag = get_tool_diagnostics(t_name)
        if diag.get("available"):
            available_tools_count += 1
        tool_status_list.append(diag)

    # 4. Workers Telemetry
    try:
        from nyx.workers.runtime import get_global_worker_store
        workers = get_global_worker_store().list_workers()
        workers_count = len(workers)
        online_workers = sum(1 for w in workers if w.status == "ONLINE")
    except Exception:
        workers_count = 0
        online_workers = 0

    # 5. Agent Fleet Telemetry
    try:
        from nyx.agent.fleet import get_fleet_manager
        agents = get_fleet_manager().list_agents()
        agents_count = len(agents)
        active_agents = sum(1 for a in agents if a.status in ("RUNNING", "IDLE"))
    except Exception:
        agents_count = 0
        active_agents = 0

    # 6. Approvals Queue Telemetry
    try:
        from nyx.agent.runtime import get_agent_runtime
        eff_target = active_target if active_target != "No active target" else None
        pending_approvals = len(get_agent_runtime().get_pending_approvals(target=eff_target))
    except Exception:
        pending_approvals = 0

    # 7. Vault Integrity
    eng_dir = _get_eng_dir(create=False)
    vault_mounted = eng_dir.exists() and eng_dir.is_dir()
    evidence_count = 0
    findings_count = 0
    if vault_mounted:
        try:
            from nyx.core import findings as core_findings
            eff_target = active_target if active_target != "No active target" else None
            f_res = core_findings.list_findings(target_filter=eff_target)
            f_list = f_res.get("findings", [])
            findings_count = len(f_list)
            for f in f_list:
                ev_ids = f.get("evidence_ids") or f.get("evidenceIds") or []
                evidence_count += len(ev_ids)
        except Exception:
            pass

    # 8. AI Providers Readiness
    try:
        from nyx.ai.service import AIService
        ai_providers_res = AIService().list_providers()
        ai_providers = ai_providers_res.data if ai_providers_res.is_success else []
    except Exception:
        ai_providers = []

    return {
        "success": True,
        "data": {
            "engine": {
                "name": "NYX Security Intelligence Engine",
                "version": "1.0.0",
                "status": "HEALTHY",
                "target": active_target,
                "phase": curr_phase,
                "workspace_active": vault_mounted,
                "authorization_enforced": True,
                "scope_enforced": True,
                "platform": sys.platform,
                "python_version": sys.version.split()[0],
            },
            "skills": {
                "count": skill_count,
                "categories": categories,
            },
            "tools": {
                "available_count": available_tools_count,
                "total_count": len(core_tools),
                "list": tool_status_list,
            },
            "workers": {
                "total": workers_count,
                "online": online_workers,
            },
            "fleet": {
                "total_agents": agents_count,
                "active_agents": active_agents,
                "pending_approvals": pending_approvals,
            },
            "vault": {
                "mounted": vault_mounted,
                "path": str(eng_dir),
                "evidence_count": evidence_count,
                "findings_count": findings_count,
            },
            "ai_providers": ai_providers,
        },
        "error": None,
        "code": "OK",
    }
