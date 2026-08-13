"""
NYX Infrastructure Filesystem & Path Utilities
"""
from __future__ import annotations
import hashlib
from pathlib import Path

# Repo root is 3 levels up from nyx/infrastructure/filesystem.py
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ENGAGEMENT_DIR_NAME = ".engagement"
VALID_STATES = ["DISCOVERY", "ANALYSIS", "VALIDATION", "REPORTING"]


def _get_eng_dir(create: bool = False, base_dir: Path | None = None) -> Path:
    """Retrieve or initialize the active engagement directory in CWD or base_dir."""
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
