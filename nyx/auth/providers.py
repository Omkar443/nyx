"""
NYX Authentication Providers & Credential Models
Defines credentials, token types (JWT, Bearer, Cookie, API Key), and auth provider configs.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


class AuthProviders:
    """Manages authentication credential profiles and token structures."""

    def __init__(self):
        self._profiles: Dict[str, Dict[str, Any]] = {}

    def register_provider(
        self,
        name: str,
        provider_type: str = "jwt",
        credentials: Optional[Dict[str, str]] = None,
        token_type: str = "Bearer",
    ) -> Dict[str, Any]:
        """Register an authentication provider configuration."""
        profile = {
            "name": name,
            "provider_type": provider_type.lower(),
            "credentials": credentials or {},
            "token_type": token_type,
            "status": "configured",
        }
        self._profiles[name] = profile
        return profile

    def get_provider(self, name: str) -> Optional[Dict[str, Any]]:
        return self._profiles.get(name)

    def list_providers(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._profiles)
