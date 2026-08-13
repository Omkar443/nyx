"""
NYX Target Surface Watcher
Polls target assets, detects differences against historical baselines, and generates change events.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.intelligence.asset_graph import AssetGraph
from nyx.intelligence.tracking import AssetTracker
from nyx.intelligence.diff_engine import DiffEngine
from nyx.intelligence.change_detection import ChangeDetector


class SurfaceWatcher:
    """Watches target attack surfaces for changes."""

    def __init__(self):
        self.tracker = AssetTracker()
        self.change_detector = ChangeDetector()

    def check_surface(self, target: str) -> Dict[str, Any]:
        """Poll target surface, record snapshot, and detect diffs."""
        graph = self.tracker.get_or_create_graph(target)

        # Retrieve previous snapshot for diff
        snapshots = self.tracker.history.get_snapshots(target)
        if len(snapshots) >= 2:
            prev_dict = snapshots[-2]["graph"]
            prev_graph = AssetGraph.from_dict(prev_dict)
            diff = DiffEngine.compare_graphs(prev_graph, graph)
            events = self.change_detector.analyze_diff(diff)
            return {"target": target, "has_changes": diff.get("has_changes", False), "events": events}

        # First snapshot
        self.tracker.record_current_state(target)
        return {"target": target, "has_changes": False, "events": []}
