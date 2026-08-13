"""
NYX Monitoring Alerts Formatter
Formats security surface change events into alert payloads.
"""
from __future__ import annotations

from typing import Any, Dict


class MonitoringAlerts:
    """Formats security change events into alert payloads."""

    @staticmethod
    def format_alert(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "alert_id": f"ALT-{event.get('event_type', 'EVT')}",
            "target": event.get("target", "example.com"),
            "severity": event.get("severity", "MEDIUM"),
            "title": f"Surface Change: {event.get('event_type')}",
            "description": event.get("description", ""),
            "data": event.get("data", {}),
        }
