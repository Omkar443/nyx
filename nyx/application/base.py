"""
NYX Base Application Service Foundation
Provides standard ServiceResult container, BaseService class, serializers, and exceptions.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import json


class ServiceException(Exception):
    """Base exception for all application service operations."""

    def __init__(self, message: str, code: str = "SERVICE_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class AuthorizationError(ServiceException):
    """Raised when an operation violates authorized target boundaries."""

    def __init__(self, message: str = "Action violates engagement authorization scope"):
        super().__init__(message, code="UNAUTHORIZED")


class ScopeBoundaryError(ServiceException):
    """Raised when target or asset is out of scope."""

    def __init__(self, message: str = "Target host/URL is outside scope boundaries"):
        super().__init__(message, code="OUT_OF_SCOPE")


@dataclass
class ServiceResult:
    """Standard result model returned by all application service operations."""

    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    code: str = "OK"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.success

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to Python dictionary."""
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "code": self.code,
            "metadata": self.metadata,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class BaseService:
    """Base parent class for all application services."""

    def ok(self, data: Optional[Dict[str, Any]] = None, message: str = "Success", metadata: Optional[Dict[str, Any]] = None) -> ServiceResult:
        """Return a successful ServiceResult."""
        res_data = data or {}
        if message and "message" not in res_data:
            res_data["message"] = message
        return ServiceResult(success=True, data=res_data, code="OK", metadata=metadata or {})

    def fail(self, message: str, error_code: str = "ERROR", details: Optional[Dict[str, Any]] = None, metadata: Optional[Dict[str, Any]] = None) -> ServiceResult:
        """Return a failed ServiceResult."""
        res_data = details or {}
        res_data["error"] = message
        return ServiceResult(success=False, data=res_data, error=message, code=error_code, metadata=metadata or {})
