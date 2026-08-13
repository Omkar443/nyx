"""
NYX Asset Tracker
Manages asset lifecycle, graph updates, and automated history recording.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
from nyx.intelligence.asset_graph import AssetGraph
from nyx.intelligence.history import AssetHistory


class AssetTracker:
    """Manages active asset graphs and records change snapshots."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.history = AssetHistory(base_dir=base_dir)
        self._graphs: Dict[str, AssetGraph] = {}

    def get_or_create_graph(self, target: str) -> AssetGraph:
        """Get or initialize target AssetGraph."""
        if target not in self._graphs:
            self._graphs[target] = AssetGraph(target=target)
        return self._graphs[target]

    def record_current_state(self, target: str) -> Dict[str, Any]:
        """Snapshot current asset state into history."""
        graph = self.get_or_create_graph(target)
        return self.history.record_snapshot(graph)
