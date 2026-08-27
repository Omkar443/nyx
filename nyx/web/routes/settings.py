"""
NYX Web API Settings & Scope Configuration Routes
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status

from nyx.web.auth import require_auth
from nyx.application.engagement_service import EngagementService
from nyx.web.dependencies import get_engagement_service

router = APIRouter(prefix="/api/v1/settings", tags=["Settings & Scope"])


class SettingsUpdateRequest(BaseModel):
    target: str
    scope: Optional[List[str]] = None
    exclusions: Optional[List[str]] = None


@router.get("", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def get_settings(
    service: EngagementService = Depends(get_engagement_service),
) -> Dict[str, Any]:
    """Retrieve active target domain, scope whitelist, and exclusion settings."""
    data = service.get_settings()
    return {"success": True, "data": data}


@router.post("", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def update_settings(
    req: SettingsUpdateRequest,
    service: EngagementService = Depends(get_engagement_service),
) -> Dict[str, Any]:
    """Update active target domain and scope whitelist in .engagement/."""
    data = service.update_settings(
        target=req.target,
        scope=req.scope,
        exclusions=req.exclusions,
    )
    return {"success": True, "data": data}


@router.post("/reset", response_model=Dict[str, Any], dependencies=[Depends(require_auth)])
async def reset_workspace(
    service: EngagementService = Depends(get_engagement_service),
) -> Dict[str, Any]:
    """Reset the engagement workspace."""
    target = service.get_target() or "example.com"
    data = service.init_engagement(target=target, reset=True, force=True)
    return {"success": True, "data": data}
