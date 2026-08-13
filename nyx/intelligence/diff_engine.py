"""
NYX Asset Diff Engine
Calculates structural diffs between two asset graph snapshots.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.intelligence.asset_graph import AssetGraph


class DiffEngine:
    """Computes differences between previous and current asset graph states."""

    @staticmethod
    def compare_graphs(previous: AssetGraph, current: AssetGraph) -> Dict[str, Any]:
        """Compute delta between previous and current asset graphs."""
        prev_sub = set(previous.subdomains)
        curr_sub = set(current.subdomains)
        new_subdomains = list(curr_sub - prev_sub)
        removed_subdomains = list(prev_sub - curr_sub)

        prev_ep = {f"{ep.get('method')}:{ep.get('path')}" for ep in previous.endpoints}
        curr_ep = {f"{ep.get('method')}:{ep.get('path')}" for ep in current.endpoints}
        new_endpoints = [ep for ep in current.endpoints if f"{ep.get('method')}:{ep.get('path')}" not in prev_ep]
        removed_endpoints = [ep for ep in previous.endpoints if f"{ep.get('method')}:{ep.get('path')}" not in curr_ep]

        prev_param = set(previous.parameters)
        curr_param = set(current.parameters)
        new_parameters = list(curr_param - prev_param)

        prev_tech = {f"{t.get('name')}:{t.get('version')}" for t in previous.technologies}
        curr_tech = {f"{t.get('name')}:{t.get('version')}" for t in current.technologies}
        new_technologies = [t for t in current.technologies if f"{t.get('name')}:{t.get('version')}" not in prev_tech]

        has_changes = bool(new_subdomains or removed_subdomains or new_endpoints or removed_endpoints or new_parameters or new_technologies)

        return {
            "target": current.target,
            "has_changes": has_changes,
            "new_subdomains": new_subdomains,
            "removed_subdomains": removed_subdomains,
            "new_endpoints": new_endpoints,
            "removed_endpoints": removed_endpoints,
            "new_parameters": new_parameters,
            "new_technologies": new_technologies,
        }
