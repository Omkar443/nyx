"""
NYX Browser Session Storage Engine
Persists authenticated browser session profiles to engagement workspace database.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.browser.context import BrowserContext


class BrowserStorage:
    """Persists browser context profiles using NYX storage abstraction."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir

    def _get_storage_file(self) -> Path:
        d = _get_eng_dir(create=True, base_dir=self.base_dir)
        db_dir = d / "database"
        db_dir.mkdir(exist_ok=True)
        return db_dir / "browser_sessions.json"

    def save_context(self, context: BrowserContext) -> None:
        """Save or update a browser context state."""
        sf = self._get_storage_file()
        data = json.loads(sf.read_text(encoding="utf-8")) if sf.exists() else {}
        data[context.session_id] = context.to_dict()
        sf.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load_context(self, session_id: str) -> Optional[BrowserContext]:
        """Load a browser context by session ID."""
        sf = self._get_storage_file()
        if sf.exists():
            try:
                data = json.loads(sf.read_text(encoding="utf-8"))
                if session_id in data:
                    return BrowserContext.from_dict(data[session_id])
            except Exception:
                pass
        return None

    def list_contexts(self) -> List[Dict[str, Any]]:
        """List all stored browser session contexts."""
        sf = self._get_storage_file()
        if sf.exists():
            try:
                data = json.loads(sf.read_text(encoding="utf-8"))
                return list(data.values())
            except Exception:
                pass
        return []
