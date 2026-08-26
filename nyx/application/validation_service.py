"""
NYX Validation Application Service
Orchestrates finding validation and quality rule verification.
"""
from __future__ import annotations
from nyx.validation import engine as validation_engine


class ValidationService:
    """Service facade for validation checks."""

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir

    def validate_finding(self, finding_id_or_path: str) -> dict:
        return validation_engine.validate_finding(finding_id_or_path, base_dir=self.base_dir)
