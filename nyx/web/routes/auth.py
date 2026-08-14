"""
NYX Web Dashboard Auth Bootstrap Routes
Provides unauthenticated local endpoints for token discovery and auth verification.
"""
from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter
from nyx.web.auth import get_or_create_api_token, verify_token

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


@router.get("/token", response_model=Dict[str, Any])
@router.get("/info", response_model=Dict[str, Any])
async def get_auth_token_info() -> Dict[str, Any]:
    """Unauthenticated local bootstrap endpoint for dashboard UI token discovery."""
    tok = get_or_create_api_token()
    return {
        "status": "ok",
        "authentication_enabled": True,
        "api_token": tok,
        "token": tok,
    }


@router.post("/verify", response_model=Dict[str, Any])
async def verify_auth_token(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Verify provided token against active API token."""
    tok = payload.get("token") or payload.get("api_token") or ""
    is_valid = verify_token(tok)
    return {
        "status": "ok" if is_valid else "invalid",
        "valid": is_valid,
    }
