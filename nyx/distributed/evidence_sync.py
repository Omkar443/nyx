"""
NYX Evidence Synchronization Module
Synchronizes evidence artifacts from remote worker nodes to central Evidence Vault with SHA-256 integrity verification.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from nyx.application.evidence_service import EvidenceService


class EvidenceSync:
    """Handles remote evidence artifact uploading and SHA-256 hash verification."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.evidence_service = EvidenceService()
        self.base_dir = base_dir

    @staticmethod
    def calculate_bytes_hash(data: bytes) -> str:
        """Calculate SHA-256 hash of raw byte data."""
        return hashlib.sha256(data).hexdigest()

    def sync_remote_evidence(
        self,
        finding_id: str,
        filename: str,
        content_bytes: bytes,
        expected_sha256: str,
        worker_id: str = "WORKER-REMOTE",
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Verify SHA-256 integrity of remote worker evidence and attach to finding."""
        calc_hash = self.calculate_bytes_hash(content_bytes)

        if expected_sha256 and calc_hash.lower() != expected_sha256.lower():
            return (
                False,
                f"[INTEGRITY ERROR] SHA-256 mismatch for file '{filename}'. Expected {expected_sha256}, got {calc_hash}.",
                {},
            )

        # Attach validated evidence artifact content as note/evidence
        res = self.evidence_service.add(
            finding_id=finding_id,
            ev_type="note",
            content=content_bytes.decode("utf-8", errors="replace"),
            description=f"Remote evidence artifact '{filename}' synchronized from worker node '{worker_id}'",
            source=f"worker_sync:{worker_id}",
        )

        status_val = res.get("status")
        if status_val == "error":
            return False, res.get("message", "Failed to attach evidence."), {}

        data = dict(res)
        data["worker_id"] = worker_id
        data["sha256_verified"] = True
        return True, "Evidence synchronized and verified successfully.", data
