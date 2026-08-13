"""
NYX Continuous Monitoring Scheduler
Manages scheduled monitoring jobs and tracks execution lifecycle states.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from nyx.monitor.jobs import MonitoringJob


class MonitoringScheduler:
    """Schedules and manages surface monitoring jobs."""

    def __init__(self):
        self._jobs: Dict[str, MonitoringJob] = {}

    def create_job(self, job_type: str, target: str, interval_seconds: int = 3600) -> MonitoringJob:
        """Create and register a monitoring job."""
        job = MonitoringJob(job_type=job_type, target=target, interval_seconds=interval_seconds)
        self._jobs[job.job_id] = job
        return job

    def run_job(self, job_id: str) -> Dict[str, Any]:
        """Execute a monitoring job and update state."""
        job = self._jobs.get(job_id)
        if not job:
            return {"success": False, "error": f"Job '{job_id}' not found."}

        job.status = "RUNNING"
        job.last_run = datetime.now().isoformat()
        job.status = "COMPLETED"
        return {"success": True, "job": job.to_dict()}

    def get_job(self, job_id: str) -> Optional[MonitoringJob]:
        return self._jobs.get(job_id)

    def list_jobs(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        jobs = [j.to_dict() for j in self._jobs.values()]
        if target:
            jobs = [j for j in jobs if j.get("target") == target]
        return jobs
