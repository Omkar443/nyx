"""
NYX Asset History Storage Module
Stores historical snapshots of asset graphs over time.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.intelligence.asset_graph import AssetGraph


class AssetHistory:
    """Stores timestamped historical versions of asset graphs."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir

    def _get_history_file(self) -> Path:
        d = _get_eng_dir(create=True, base_dir=self.base_dir)
        db_dir = d / "database"
        db_dir.mkdir(exist_ok=True)
        return db_dir / "asset_history.json"

    def record_snapshot(self, graph: AssetGraph) -> Dict[str, Any]:
        """Record a timestamped snapshot of an asset graph."""
        hf = self._get_history_file()
        history = json.loads(hf.read_text(encoding="utf-8")) if hf.exists() else []

        snapshot = {
            "target": graph.target,
            "timestamp": graph.updated_at,
            "graph": graph.to_dict(),
        }
        history.append(snapshot)
        hf.write_text(json.dumps(history, indent=2), encoding="utf-8")
        return snapshot

    def get_snapshots(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve historical snapshots."""
        hf = self._get_history_file()
        if not hf.exists():
            return []
        try:
            history = json.loads(hf.read_text(encoding="utf-8"))
            if target:
                from nyx.security.authorization import parse_target_tuple
                from nyx.ai.context import _matches_target_endpoint
                _, t_host, _ = parse_target_tuple(target)
                filtered = []
                for s in history:
                    s_target = s.get("target", "")
                    _, s_host, _ = parse_target_tuple(s_target)
                    if (t_host and s_host == t_host) or _matches_target_endpoint(s_target, target):
                        filtered.append(s)
                return filtered
            return history
        except Exception:
            return []
