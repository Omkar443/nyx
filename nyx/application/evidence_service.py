"""
NYX Evidence Storage Application Service
Orchestrates evidence vault management, hashing, sanitization, and verification.
"""
from __future__ import annotations

from typing import Any
from nyx.core import evidence as core_evidence


class EvidenceService:
    """Service facade for evidence vault management."""

    def add(
        self,
        finding_id: str,
        ev_type: str = "note",
        content: str | None = None,
        file: str | None = None,
        description: str = "",
        source: str = "manual",
    ) -> dict[str, Any]:
        return core_evidence.add_evidence(
            finding_id=finding_id,
            ev_type=ev_type,
            content=content,
            file=file,
            description=description,
            source=source,
        )

    def list_evidence(self, finding_id: str) -> dict[str, Any]:
        return core_evidence.list_evidence(finding_id=finding_id)

    def show(self, evidence_id: str) -> dict[str, Any]:
        return core_evidence.show_evidence(evidence_id=evidence_id)

    def show_evidence(self, evidence_id: str) -> dict[str, Any]:
        return self.show(evidence_id)

    def verify(self, evidence_id: str) -> dict[str, Any]:
        return core_evidence.verify_evidence(evidence_id=evidence_id)

    def verify_evidence(self, evidence_id: str) -> dict[str, Any]:
        return self.verify(evidence_id)
