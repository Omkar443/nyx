"""
NYX AI Memory System
Persists AI decision logs, target research history, and failed attack vectors across sessions.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.infrastructure.filesystem import _get_eng_dir


class AIMemory:
    """Manages persistent AI memory database under .engagement/database/ai_memory.json."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir

    def _get_memory_file(self) -> Path:
        d = _get_eng_dir(create=True, base_dir=self.base_dir)
        db_dir = d / "database"
        db_dir.mkdir(parents=True, exist_ok=True)
        return db_dir / "ai_memory.json"

    def _load_data(self) -> Dict[str, Any]:
        mf = self._get_memory_file()
        if mf.exists():
            try:
                return json.loads(mf.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "decisions": [],
            "failed_approaches": [],
            "technology_history": {},
            "notes": [],
        }

    def _save_data(self, data: Dict[str, Any]) -> None:
        mf = self._get_memory_file()
        mf.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def record_decision(self, decision_type: str, details: Dict[str, Any]) -> None:
        """Record an AI decision entry."""
        data = self._load_data()
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": decision_type,
            "details": details,
        }
        data["decisions"].append(entry)
        self._save_data(data)

    def record_failed_approach(self, target: str, vector: str, reason: str) -> None:
        """Record a failed approach/test vector to prevent repeating it."""
        data = self._load_data()
        entry = {
            "target": target,
            "vector": vector,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        }
        if entry not in data["failed_approaches"]:
            data["failed_approaches"].append(entry)
            self._save_data(data)

    def get_failed_approaches(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recorded failed approaches."""
        data = self._load_data()
        approaches = data.get("failed_approaches", [])
        if target:
            return [a for a in approaches if a.get("target") == target]
        return approaches

    def get_decisions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent AI decision entries."""
        data = self._load_data()
        decisions = data.get("decisions", [])
        return decisions[-limit:] if limit > 0 else decisions

    def clear(self) -> None:
        """Reset memory store."""
        data = {
            "decisions": [],
            "failed_approaches": [],
            "technology_history": {},
            "notes": [],
        }
        self._save_data(data)
