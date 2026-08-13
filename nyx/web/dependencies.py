"""
NYX Web API Dependency Injectors
Provides clean application service factory instances and request correlation context.
"""
from __future__ import annotations

import uuid
from typing import Optional
from fastapi import Header, Request

from nyx.application.engagement_service import EngagementService
from nyx.application.recon_service import ReconService
from nyx.application.finding_service import FindingService
from nyx.application.evidence_service import EvidenceService
from nyx.application.execution_service import ExecutionService
from nyx.application.ai_service import AIService
from nyx.application.analysis_service import AnalysisService
from nyx.application.validation_service import ValidationService
from nyx.application.mission_service import MissionService
from nyx.application.skill_service import SkillService


def get_request_id(x_request_id: Optional[str] = Header(None, alias="X-Request-ID")) -> str:
    """Return existing or new correlation request ID."""
    return x_request_id or f"REQ-{uuid.uuid4().hex[:8].upper()}"


def get_engagement_service() -> EngagementService:
    return EngagementService()


def get_recon_service() -> ReconService:
    return ReconService()


def get_finding_service() -> FindingService:
    return FindingService()


def get_evidence_service() -> EvidenceService:
    return EvidenceService()


def get_execution_service() -> ExecutionService:
    return ExecutionService()


def get_ai_service() -> AIService:
    return AIService()


def get_analysis_service() -> AnalysisService:
    return AnalysisService()


def get_validation_service() -> ValidationService:
    return ValidationService()


def get_mission_service() -> MissionService:
    return MissionService()


def get_skill_service() -> SkillService:
    return SkillService()
