"""
NYX Infrastructure Tool Discovery Engine
"""
from __future__ import annotations
import os
import shutil
import sys
from pathlib import Path

_TOOL_CACHE: dict[str, str | None] = {}


def get_cmd_path(name: str) -> str | None:
    """Centralized tool discovery function for Windows, Linux, and Kali WSL.
    Checks PATH via shutil.which(), then falls back to common Go/security tool installation paths.
    """
    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]

    found = shutil.which(name)
    if found:
        _TOOL_CACHE[name] = found
        return found

    home = Path.home()
    userprofile = os.environ.get("USERPROFILE")
    exts = ["", ".exe", ".bat", ".cmd"] if sys.platform == "win32" else ["", ".exe"]

    search_dirs = [
        home / "go" / "bin",
        home / ".local" / "bin",
        Path("/usr/local/bin"),
        Path("/usr/bin"),
        Path("/opt/go/bin"),
    ]
    if userprofile:
        search_dirs.append(Path(userprofile) / "go" / "bin")

    for s_dir in search_dirs:
        if s_dir.exists() and s_dir.is_dir():
            for ext in exts:
                cand = s_dir / f"{name}{ext}"
                if cand.exists() and cand.is_file():
                    _TOOL_CACHE[name] = str(cand)
                    return str(cand)

    _TOOL_CACHE[name] = None
    return None


def has_cmd(name: str) -> bool:
    """Return True if tool command is discoverable on system."""
    return get_cmd_path(name) is not None
