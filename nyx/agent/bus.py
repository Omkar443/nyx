"""
NYX Agent Communication Message Bus
Allows specialized security research agents to exchange structured events and messages.
Stored via NYX workspace storage persistence abstraction.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from nyx.infrastructure.filesystem import _get_eng_dir


class AgentMessageBus:
    """Central event broadcasting bus for multi-agent coordination."""

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir
        self._listeners: List[Callable[[Dict[str, Any]], None]] = []

    def _get_history_file(self) -> Path:
        d = _get_eng_dir(create=True, base_dir=self.base_dir)
        db_dir = d / "database"
        db_dir.mkdir(exist_ok=True)
        return db_dir / "agent_events.json"

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Subscribe a listener callback to event stream."""
        if callback not in self._listeners:
            self._listeners.append(callback)

    def publish(
        self,
        sender: str,
        receiver: str,
        event_type: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Publish a structured inter-agent event message."""
        msg = {
            "sender": sender,
            "receiver": receiver,
            "event_type": event_type,
            "payload": payload,
            "timestamp": datetime.now().isoformat(),
        }

        # Store event history using NYX storage abstraction
        hf = self._get_history_file()
        history_data = json.loads(hf.read_text(encoding="utf-8")) if hf.exists() else []
        history_data.append(msg)
        hf.write_text(json.dumps(history_data, indent=2), encoding="utf-8")

        for callback in self._listeners:
            try:
                callback(msg)
            except Exception:
                pass

        return msg

    def get_history(
        self,
        event_type: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve message history filtered by event type or agent ID."""
        hf = self._get_history_file()
        if not hf.exists():
            return []

        try:
            res = json.loads(hf.read_text(encoding="utf-8"))
        except Exception:
            return []

        if event_type:
            res = [m for m in res if m.get("event_type") == event_type]
        if agent_id:
            res = [m for m in res if m.get("sender") == agent_id or m.get("receiver") == agent_id]

        return res
