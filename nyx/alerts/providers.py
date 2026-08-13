"""
NYX Alert Providers
Handles alert delivery channels: Dashboard notifications, Webhook payloads, and SIEM integration foundation.
"""
from __future__ import annotations

from typing import Any, Dict, List


class AlertProviders:
    """Manages notification channels (Dashboard, Webhook, SIEM)."""

    def __init__(self):
        self._webhooks: List[str] = []

    def add_webhook(self, url: str) -> None:
        if url not in self._webhooks:
            self._webhooks.append(url)

    def dispatch(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch alert to registered channels."""
        # Foundation webhook delivery simulation
        return {
            "delivered_dashboard": True,
            "webhooks_triggered_count": len(self._webhooks),
            "alert": alert,
        }
