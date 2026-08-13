"""
NYX Alert Events Definition
Defines alert types, severity levels, and event payloads for surface notifications.
"""
from __future__ import annotations

from typing import Any, Dict


class AlertEvents:
    """Alert event payload generator."""

    @staticmethod
    def create_event(target: str, event_type: str, severity: str, title: str, description: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target": target,
            "event_type": event_type,
            "severity": severity.upper(),
            "title": title,
            "description": description,
            "data": data,
        }
