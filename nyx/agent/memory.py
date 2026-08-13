"""
NYX Agent Persistent Memory Module
Persists agent decision logs, research plans, approved executions, and rejected hypotheses.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from nyx.infrastructure.filesystem import _get_eng_dir


class AgentMemory:
    """Persists agent decision logs and research history in engagement workspace."""

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir

    def _get_memory_file(self) -> Path:
        d = _get_eng_dir(create=True, base_dir=self.base_dir)
        db_dir = d / "database"
        db_dir.mkdir(exist_ok=True)
        return db_dir / "agent_memory.json"

    def record_decision(self, decision: Dict[str, Any]) -> None:
        """Record an agent decision log entry."""
        mf = self._get_memory_file()
        mem_data = json.loads(mf.read_text(encoding="utf-8")) if mf.exists() else {"decisions": [], "plans": []}
        mem_data.setdefault("decisions", []).append(decision)
        mf.write_text(json.dumps(mem_data, indent=2), encoding="utf-8")

    def record_plan(self, plan: Dict[str, Any]) -> None:
        """Record a research plan."""
        mf = self._get_memory_file()
        mem_data = json.loads(mf.read_text(encoding="utf-8")) if mf.exists() else {"decisions": [], "plans": []}
        mem_data.setdefault("plans", []).append(plan)
        mf.write_text(json.dumps(mem_data, indent=2), encoding="utf-8")

    def get_history(self) -> Dict[str, Any]:
        """Retrieve stored agent decision history and plans."""
        mf = self._get_memory_file()
        if mf.exists():
            try:
                return json.loads(mf.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"decisions": [], "plans": []}
