"""
NYX Web API Intelligence & AI Routes
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from nyx.web.schemas import AIPlanRequest, AIAutonomousRequest
from nyx.web.auth import require_auth
from nyx.application.ai_service import AIService
from nyx.application.skill_service import SkillService
from nyx.application.analysis_service import AnalysisService
from nyx.web.dependencies import get_ai_service, get_skill_service, get_analysis_service

router = APIRouter(prefix="/api/v1", tags=["Intelligence & AI"])


def _parse_res(res: Any) -> tuple[bool, Dict[str, Any]]:
    if isinstance(res, dict):
        return res.get("success", True), res
    if hasattr(res, "to_dict"):
        d = res.to_dict()
        ok = d.get("success", getattr(res, "is_success", True))
        return ok, d
    return True, {"success": True, "data": res}


@router.get("/intelligence/context", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_intelligence_context(
    target: str | None = Query(None, description="Target domain"),
    service: AIService = Depends(get_ai_service),
) -> Dict[str, Any]:
    """Retrieve aggregated target security context for AI reasoning."""
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target() or "No active target"
    _, data = _parse_res(service.get_context(active_target))
    return data


@router.get("/intelligence/surface", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_intelligence_surface(
    target: str | None = Query(None, description="Target domain"),
    service: AnalysisService = Depends(get_analysis_service),
) -> Dict[str, Any]:
    """Retrieve attack surface ranking intelligence."""
    from nyx.core.engagement import get_engagement_target
    active_target = target or get_engagement_target() or "No active target"
    _, data = _parse_res(service.rank_surface(active_target))
    return data


@router.get("/skills", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_skills_catalog(
    category: Optional[str] = Query(None, description="Optional category filter"),
    service: SkillService = Depends(get_skill_service),
) -> Dict[str, Any]:
    """List available NYX security research skills catalog with dynamic count."""
    _, data = _parse_res(service.get_skills_result(category=category))
    return data


@router.get("/skills/stats", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_skills_stats(
    service: SkillService = Depends(get_skill_service),
) -> Dict[str, Any]:
    """Retrieve dynamic, live skill inventory count and category distribution."""
    _, data = _parse_res(service.get_skills_stats_result())
    return data


@router.get("/skills/recommend", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def recommend_skills(
    url: Optional[str] = Query(None, description="Target endpoint or path"),
    tech: Optional[str] = Query(None, description="Technology name"),
    service: SkillService = Depends(get_skill_service),
) -> Dict[str, Any]:
    """Recommend security research skills based on detected tech stack or URL patterns."""
    _, data = _parse_res(service.recommend_skills_result(url=url or "", technology=tech))
    return data


@router.get("/knowledge/search", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def search_knowledge_base(
    query: str = Query(..., description="Search query"),
) -> Dict[str, Any]:
    """Search NYX security knowledge base and research mappings."""
    from nyx.core import knowledge
    results = knowledge.search_knowledge(keyword=query)
    matched_vulns = results.get("matched_vulnerabilities", [])
    count = len(matched_vulns) + len(results.get("matched_technologies", []))
    return {
        "success": True,
        "data": {"query": query, "results": results, "count": count},
        "error": None,
        "code": "OK",
    }


@router.get("/ai/providers", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def list_ai_providers(service: AIService = Depends(get_ai_service)) -> Dict[str, Any]:
    """List registered AI providers (Gemini, NYX AI, OpenAI, Local LLM)."""
    _, data = _parse_res(service.list_providers())
    return data


@router.get("/ai/active-provider", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_active_ai_provider(service: AIService = Depends(get_ai_service)) -> Dict[str, Any]:
    """Get the currently active or detected default AI provider."""
    from nyx.ai.manager import detect_default_provider
    active = service.manager.active_provider_name or detect_default_provider()
    return {
        "success": True,
        "data": {
            "active_provider": active,
            "detected_default": detect_default_provider(),
        },
        "error": None,
        "code": "OK",
    }


@router.post("/ai/test", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def test_ai_provider(
    provider: Optional[str] = Query(None, description="Optional AI provider name (e.g. gemini)"),
    service: AIService = Depends(get_ai_service),
) -> Dict[str, Any]:
    """Run health check test for specified or active AI provider."""
    _, data = _parse_res(service.test_provider(provider_name=provider))
    return data


@router.post("/ai/plan", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def generate_ai_mission_plan(
    req: Optional[AIPlanRequest] = None,
    target: Optional[str] = Query(None, description="Target domain (fallback if not in body)"),
    provider: Optional[str] = Query(None, description="Optional AI provider name"),
    vulnerability_type: Optional[str] = Query(None, description="Optional vulnerability class"),
    service: AIService = Depends(get_ai_service),
) -> Dict[str, Any]:
    """Generate a policy-validated multi-step mission plan using AI provider reasoning."""
    active_target = (req.target if req and req.target else target) or ""
    active_provider = (req.provider if req and req.provider else provider)
    active_vuln = (req.vulnerability_type if req and req.vulnerability_type else vulnerability_type)
    active_context = req.context if req else None

    if not active_target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "TARGET_REQUIRED", "message": "Target parameter is required in request body or query."},
        )

    import asyncio
    plan_res = await asyncio.to_thread(
        service.plan_mission,
        active_target,
        vulnerability_type=active_vuln,
        provider_name=active_provider,
        context_override=active_context,
    )
    ok, data = _parse_res(plan_res)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": data.get("code", "PLAN_FAILED"), "message": data.get("error", "Failed to plan mission.")},
        )
    return data


@router.post("/ai/autonomous-run", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def run_ai_autonomous_loop(
    req: AIAutonomousRequest,
    service: AIService = Depends(get_ai_service),
) -> Dict[str, Any]:
    """Execute autonomous security mission loop."""
    import asyncio
    if not req.target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "TARGET_REQUIRED", "message": "Target parameter is required in request body."},
        )

    from nyx.execution.policy import normalize_target
    target_clean = normalize_target(req.target)
    res = await asyncio.to_thread(
        service.planner.run_autonomous_loop,
        target=target_clean,
        provider_name=req.provider_name,
        active_permitted=req.active_permitted,
        max_iterations=req.max_iterations,
    )
    if res.get("status") == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "SCOPE_ERROR" if res.get("error") == "out of scope" else "LOOP_FAILED", "message": res.get("error", "Autonomous loop failed."), "details": res},
        )
    return res
