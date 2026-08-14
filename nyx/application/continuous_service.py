"""
NYX Continuous Intelligence Application Service
Facade orchestrating monitoring jobs, asset history, change detection, alerts, research opportunities, and knowledge protection.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.application.base import BaseService, ServiceResult
from nyx.monitor.scheduler import MonitoringScheduler
from nyx.monitor.watcher import SurfaceWatcher
from nyx.intelligence.tracking import AssetTracker
from nyx.intelligence.history import AssetHistory
from nyx.intelligence.change_detection import ChangeDetector
from nyx.alerts.manager import AlertManager
from nyx.research.opportunities import OpportunityEngine
from nyx.knowledge.protection import KnowledgeProtection


class ContinuousService(BaseService):
    """Facade for continuous security intelligence operations."""

    def __init__(self):
        super().__init__()
        self.scheduler = MonitoringScheduler()
        self.watcher = SurfaceWatcher()
        self.tracker = AssetTracker()
        self.history = AssetHistory()
        self.change_detector = ChangeDetector()
        self.alert_manager = AlertManager()
        self.opportunity_engine = OpportunityEngine()
        self.knowledge_protection = KnowledgeProtection()

    def start_monitoring_job(self, target: str, job_type: str = "recon_refresh") -> ServiceResult:
        """Start a new continuous monitoring job."""
        job = self.scheduler.create_job(job_type=job_type, target=target)
        run_res = self.scheduler.run_job(job.job_id)
        
        # Trigger surface watch check
        watch_res = self.watcher.check_surface(target)
        events = watch_res.get("events", [])
        
        for evt in events:
            # Raise alerts and map to research opportunities
            self.alert_manager.raise_alert(target=target, title=evt.get("description", ""), severity=evt.get("severity", "MEDIUM"))
            self.opportunity_engine.analyze_event(evt)

        return self.ok(data={"job": job.to_dict(), "watch_result": watch_res}, message=f"Monitoring job '{job.job_id}' started for target '{target}'.")

    def get_monitoring_status(self) -> ServiceResult:
        jobs = self.scheduler.list_jobs()
        return self.ok(data={"jobs_count": len(jobs), "jobs": jobs}, message="Retrieved monitoring status.")

    def get_asset_history(self, target: Optional[str] = None) -> ServiceResult:
        t_name = target
        if not t_name:
            from nyx.infrastructure.filesystem import _get_eng_dir
            d = _get_eng_dir()
            if d.exists():
                t_file = d / "target.yaml"
                if t_file.exists():
                    for line in t_file.read_text(encoding="utf-8").splitlines():
                        if line.strip().startswith("domain:") or line.strip().startswith("name:"):
                            t_name = line.split(":", 1)[1].strip().strip('"').strip("'")
                            break
        
        target_to_sync = t_name or "example.com"
        self.tracker.record_current_state(target_to_sync)

        snapshots = self.history.get_snapshots(target=target)
        return self.ok(data={"snapshots_count": len(snapshots), "snapshots": snapshots}, message="Retrieved asset history snapshots.")

    def list_changes(self, target: Optional[str] = None) -> ServiceResult:
        events = self.change_detector.list_events(target=target)
        return self.ok(data={"changes_count": len(events), "changes": events}, message="Retrieved change detection events.")

    def list_alerts(self, target: Optional[str] = None) -> ServiceResult:
        alerts = self.alert_manager.list_alerts(target=target)
        return self.ok(data={"alerts_count": len(alerts), "alerts": alerts}, message="Retrieved alerts.")

    def list_research_opportunities(self, target: Optional[str] = None) -> ServiceResult:
        opps = self.opportunity_engine.list_opportunities(target=target)
        return self.ok(data={"opportunities_count": len(opps), "opportunities": opps}, message="Retrieved research opportunities.")

    def backup_knowledge(self) -> ServiceResult:
        res = self.knowledge_protection.create_backup()
        return self.ok(data=res, message="Created knowledge asset backup.")

    def verify_knowledge(self) -> ServiceResult:
        res = self.knowledge_protection.verify_integrity()
        if not res.get("intact"):
            return self.fail(message=res.get("message", "Verification failed."), error_code="KNOWLEDGE_CORRUPTED")
        return self.ok(data=res, message=res.get("message", "Knowledge assets verified intact."))
