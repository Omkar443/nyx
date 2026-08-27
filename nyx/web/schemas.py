"""
NYX Web API Pydantic Schemas
Defines typed request/response boundary models for the web dashboard platform.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# --- Health & Error Schemas ---
class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    app_name: str = "NYX Security Operations Dashboard"
    workspace_active: bool = False
    target: Optional[str] = None
    authentication_enabled: bool = True
    api_token: Optional[str] = None
    skills_count: Optional[int] = None


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    error: ErrorDetail


# --- Mission / Engagement Schemas ---
class MissionInitRequest(BaseModel):
    target: str = Field(..., description="Target domain or IP")
    reset: bool = False
    force: bool = False


class MissionStateRequest(BaseModel):
    new_state: Optional[str] = Field(None, description="New workflow state (DISCOVERY, ANALYSIS, VALIDATION, REPORTING)")
    mode: Optional[str] = Field(None, description="Workflow mode (RESEARCH, STRICT)")
    force: bool = False


class MissionResponse(BaseModel):
    status: str
    target: Optional[str] = None
    phase: Optional[str] = None
    mode: Optional[str] = None
    workspace_path: Optional[str] = None
    message: Optional[str] = None


# --- Surface & Assets Schemas ---
class AssetResponse(BaseModel):
    domain: str
    in_scope: bool = True
    subdomains_count: int = 0
    endpoints_count: int = 0


class EndpointResponse(BaseModel):
    url: str
    method: str = "GET"
    in_scope: bool = True
    discovered_at: Optional[str] = None


class TechnologyResponse(BaseModel):
    name: str
    version: Optional[str] = None
    category: Optional[str] = None


class SurfaceResponse(BaseModel):
    target: str
    in_scope: bool = True
    domains: List[str] = []
    endpoints: List[Dict[str, Any]] = []
    technologies: List[Dict[str, Any]] = []
    risk_score: float = 0.0


# --- Findings Schemas ---
class FindingCreateRequest(BaseModel):
    title: str
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    vulnerability: Optional[str] = "IDOR"
    severity: str = Field("Medium", description="Low, Medium, High, Critical")
    description: Optional[str] = None
    tags: List[str] = []


class FindingTransitionRequest(BaseModel):
    new_state: str = Field(..., description="HYPOTHESIS, VERIFIED, REJECTED, SUBMITTED")
    reason: str = Field(..., description="Mandatory reason for state transition")


class FindingTriageRequest(BaseModel):
    finding_file: Optional[str] = None


class FindingResponse(BaseModel):
    finding_id: str
    title: str
    severity: str
    status: str
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    vulnerability: Optional[str] = None
    confidence: Optional[float] = 0.0
    created_at: Optional[str] = None
    evidence_ids: List[str] = []


# --- Evidence Schemas ---
class EvidenceVerifyRequest(BaseModel):
    evidence_id: str


class EvidenceResponse(BaseModel):
    evidence_id: str
    finding_id: Optional[str] = None
    type: str
    description: Optional[str] = None
    content: Optional[str] = None
    sanitized: bool = True
    redactions_count: int = 0
    sha256: Optional[str] = None
    created_at: Optional[str] = None


# --- Intelligence & AI Schemas ---
class IntelligenceContextResponse(BaseModel):
    target: str
    in_scope: bool
    phase: str
    technologies: List[str] = []
    endpoints_count: int = 0
    skills_matched: List[str] = []
    previous_findings_count: int = 0
    failed_approaches_count: int = 0


class SkillResponse(BaseModel):
    name: str
    category: Optional[str] = None
    description: Optional[str] = None
    path: Optional[str] = None


class SkillStatsResponse(BaseModel):
    skill_count: int
    count: int
    categories: Optional[Dict[str, int]] = None


# --- Execution Schemas ---
class ExecutionRequestSchema(BaseModel):
    tool_name: str
    target: str
    arguments: List[str] = []
    dry_run: bool = False
    active_permitted: bool = False


class ExecutionResponseSchema(BaseModel):
    execution_id: str
    tool_name: str
    target: str
    status: str
    exit_code: int = 0
    stdout: Optional[str] = ""
    stderr: Optional[str] = ""
    duration_sec: Optional[float] = 0.0
    dry_run: bool = False
    authorized: bool = True
    scope_status: str = "IN_SCOPE"


# --- WebSocket Event Schema ---
class EventMessage(BaseModel):
    event: str
    timestamp: str
    mission_id: Optional[str] = None
    data: Dict[str, Any] = {}
