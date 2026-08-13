"""
NYX Alert Manager
Central alert queue and notification dispatcher.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from nyx.alerts.providers import AlertProviders


class AlertManager:
    """Manages active alert queue and notification dispatching."""

    def __init__(self):
        self.providers = AlertProviders()
        self._alerts: Dict[str, Dict[str, Any]] = {}

    def raise_alert(self, target: str, title: str, severity: str = "MEDIUM", description: str = "", data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create and dispatch a security alert."""
        alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
        alert = {
            "alert_id": alert_id,
            "target": target,
            "title": title,
            "severity": severity.upper(),
            "description": description,
            "data": data or {},
            "read": False,
            "created_at": datetime.now().isoformat(),
        }
        self._alerts[alert_id] = alert
        self.providers.dispatch(alert)
        return alert

    def list_alerts(self, target: Optional[str] = None, unread_only: bool = False) -> List[Dict[str, Any]]:
        res = list(self._alerts.values())
        if target:
            res = [a for a in res if a.get("target") == target]
        if unread_only:
            res = [a for a in res if not a.get("read")]
        return sorted(res, key=lambda x: x.get("created_at", ""), reverse=True)
