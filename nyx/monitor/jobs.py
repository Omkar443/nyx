"""
NYX Continuous Monitoring Jobs Definition
Defines recurring scheduled jobs for surface discovery, tech drift, endpoint comparison, and JS change detection.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


class MonitoringJob:
    """Represents a scheduled surface monitoring job."""

    def __init__(self, job_type: str, target: str, interval_seconds: int = 3600):
        self.job_id = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        self.job_type = job_type
        self.target = target
        self.interval_seconds = interval_seconds
        self.status = "CREATED"  # CREATED, RUNNING, COMPLETED, FAILED
        self.created_at = datetime.now().isoformat()
        self.last_run = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "job_type": self.job_type,
            "target": self.target,
            "interval_seconds": self.interval_seconds,
            "status": self.status,
            "created_at": self.created_at,
            "last_run": self.last_run,
        }
