"""
NYX Infrastructure Filesystem & Path Utilities
"""
from __future__ import annotations
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

# Repo root is 3 levels up from nyx/infrastructure/filesystem.py
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ENGAGEMENT_DIR_NAME = ".engagement"
VALID_STATES = ["DISCOVERY", "ANALYSIS", "VALIDATION", "REPORTING"]


def _get_eng_dir(create: bool = False, base_dir: Path | None = None) -> Path:
    """Retrieve or initialize the active engagement directory in base_dir or CWD."""
    base = Path(base_dir) if base_dir else Path.cwd()
    d = base / ENGAGEMENT_DIR_NAME
    if create and not d.exists():
        d.mkdir(parents=True, exist_ok=True)
        (d / "reports").mkdir(exist_ok=True)
        (d / "database" / "findings").mkdir(parents=True, exist_ok=True)
    return d


def calculate_file_hash(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write_json(file_path: Path, data: Any, indent: int = 2) -> None:
    """Atomically write JSON data to file using a temporary file and atomic rename with retry on Windows."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(dir=str(file_path.parent), prefix=".tmp_")
    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(5):
            try:
                os.replace(temp_path, str(file_path))
                break
            except PermissionError:
                if attempt == 4:
                    file_path.write_text(json.dumps(data, indent=indent), encoding="utf-8")
                    if os.path.exists(temp_path):
                        try:
                            os.remove(temp_path)
                        except Exception:
                            pass
                    break
                import time
                time.sleep(0.05)
    except Exception:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        raise
