"""
NYX Change Detection Module
Detects high-value surface changes (new endpoints, parameters, technologies, JS files, auth changes).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.intelligence.asset_graph import AssetGraph
from nyx.intelligence.diff_engine import DiffEngine


class ChangeDetector:
    """Detects security-relevant attack surface changes."""

    def __init__(self):
        self._change_events: List[Dict[str, Any]] = []

    def analyze_diff(self, diff: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a diff report and generate security change events."""
        events = []
        target = diff.get("target", "example.com")

        # New Endpoints
        for ep in diff.get("new_endpoints", []):
            evt = {
                "target": target,
                "event_type": "NEW_ENDPOINT",
                "severity": "MEDIUM",
                "description": f"New endpoint detected: {ep.get('method')} {ep.get('path')}",
                "data": ep,
            }
            events.append(evt)

        # New Parameters
        for param in diff.get("new_parameters", []):
            evt = {
                "target": target,
                "event_type": "NEW_PARAMETER",
                "severity": "LOW",
                "description": f"New input parameter detected: '{param}'",
                "data": {"parameter": param},
            }
            events.append(evt)

        # New Technologies
        for tech in diff.get("new_technologies", []):
            evt = {
                "target": target,
                "event_type": "NEW_TECHNOLOGY",
                "severity": "INFO",
                "description": f"New technology detected: {tech.get('name')} {tech.get('version')}",
                "data": tech,
            }
            events.append(evt)

        self._change_events.extend(events)
        return events

    def list_events(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all detected change events."""
        if target:
            from nyx.security.authorization import parse_target_tuple
            from nyx.ai.context import _matches_target_endpoint
            _, t_host, _ = parse_target_tuple(target)
            filtered = []
            for e in self._change_events:
                e_target = e.get("target", "")
                _, e_host, _ = parse_target_tuple(e_target)
                if (t_host and e_host == t_host) or _matches_target_endpoint(e_target, target):
                    filtered.append(e)
            return filtered
        return list(self._change_events)
