"""
NYX Web Authentication Module
Provides local token authentication dependencies for REST endpoints and WebSocket connections.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, Query, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from nyx.infrastructure.filesystem import _get_eng_dir

_bearer_scheme = HTTPBearer(auto_error=False)
_CACHED_TOKEN: Optional[str] = None


def get_or_create_api_token() -> str:
    """Retrieve active API token from NYX_API_TOKEN env or persistent workspace token file."""
    global _CACHED_TOKEN
    env_token = os.environ.get("NYX_API_TOKEN")
    if env_token and env_token.strip():
        return env_token.strip()

    if _CACHED_TOKEN:
        return _CACHED_TOKEN

    try:
        d = _get_eng_dir(create=True)
        token_file = d / ".web_token"
        if token_file.exists():
            tok = token_file.read_text(encoding="utf-8").strip()
            if tok:
                _CACHED_TOKEN = tok
                return tok

        # Generate fresh secure random 32-byte hex token
        tok = secrets.token_hex(32)
        token_file.write_text(tok, encoding="utf-8")
        _CACHED_TOKEN = tok
        return tok
    except Exception:
        # Fallback local in-memory token
        if not _CACHED_TOKEN:
            _CACHED_TOKEN = secrets.token_hex(32)
        return _CACHED_TOKEN


def verify_token(provided_token: Optional[str]) -> bool:
    """Verify provided token against configured NYX token."""
    if not provided_token:
        return False
    expected = get_or_create_api_token()
    return secrets.compare_digest(provided_token.strip(), expected.strip())


async def require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
) -> str:
    """FastAPI dependency enforcing valid API token authentication."""
    token: Optional[str] = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    elif x_api_token:
        token = x_api_token

    if not verify_token(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Invalid or missing API authentication token."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token or ""


async def verify_ws_token(token: Optional[str] = Query(None)) -> bool:
    """Verify WebSocket query token authentication."""
    if not token or not verify_token(token):
        return False
    return True
