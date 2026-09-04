"""
NYX Asset Tracker
Manages asset lifecycle, graph updates, and automated history recording.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.intelligence.asset_graph import AssetGraph
from nyx.intelligence.history import AssetHistory


class AssetTracker:
    """Manages active asset graphs and records change snapshots."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir
        self.history = AssetHistory(base_dir=base_dir)
        self._graphs: Dict[str, AssetGraph] = {}

    def sync_from_engagement(self, target: str) -> AssetGraph:
        """Populate or update target AssetGraph using active engagement inventory."""
        graph = self._graphs.get(target) or AssetGraph(target=target)
        self._graphs[target] = graph
        d = _get_eng_dir(base_dir=self.base_dir)
        if not d.exists():
            return graph

        # Ingest endpoints inventory
        ep_file = d / "endpoints.json"
        if ep_file.exists():
            try:
                from nyx.ai.context import _matches_target_endpoint

                def _is_ep_for_target(ep_url: str, tgt: str) -> bool:
                    if not ep_url or not tgt:
                        return False
                    if ep_url.startswith("/") or ep_url.startswith("?"):
                        return True
                    return _matches_target_endpoint(ep_url, tgt)

                raw_eps = json.loads(ep_file.read_text(encoding="utf-8"))
                eps_list = raw_eps if isinstance(raw_eps, list) else raw_eps.get("endpoints", []) if isinstance(raw_eps, dict) else []
                for ep in eps_list:
                    if isinstance(ep, dict):
                        url = ep.get("url") or ep.get("path") or ""
                        if not url or not _is_ep_for_target(url, target):
                            continue
                        method = ep.get("method", "GET")
                        params = ep.get("params", [])
                        graph.add_endpoint(url, method=method, params=params)
                        host = ep.get("host")
                        if host and host != target and (host.endswith(f".{target}") or f".{host}" in target):
                            graph.add_subdomain(host)
                    elif isinstance(ep, str):
                        if ep and _is_ep_for_target(ep, target):
                            graph.add_endpoint(ep)
            except Exception:
                pass

        # Ingest technologies inventory
        tech_file = d / "technologies.json"
        if tech_file.exists():
            try:
                raw_tech = json.loads(tech_file.read_text(encoding="utf-8"))
                if isinstance(raw_tech, dict):
                    for cat, items in raw_tech.items():
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, str):
                                    graph.add_technology(name=item, category=cat)
                                elif isinstance(item, dict):
                                    graph.add_technology(
                                        name=item.get("name", ""),
                                        category=item.get("category", cat),
                                        version=item.get("version", "")
                                    )
                elif isinstance(raw_tech, list):
                    for item in raw_tech:
                        if isinstance(item, str):
                            graph.add_technology(name=item)
                        elif isinstance(item, dict):
                            graph.add_technology(
                                name=item.get("name", ""),
                                category=item.get("category", "web"),
                                version=item.get("version", "")
                            )
            except Exception:
                pass

        return graph

    def get_or_create_graph(self, target: str) -> AssetGraph:
        """Get or initialize target AssetGraph."""
        return self.sync_from_engagement(target)

    def record_current_state(self, target: str) -> Dict[str, Any]:
        """Snapshot current asset state into history."""
        graph = self.sync_from_engagement(target)
        return self.history.record_snapshot(graph)
