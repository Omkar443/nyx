"""
NYX Infrastructure Tool Discovery Engine
"""
from __future__ import annotations
import os
import shutil
import sys
from pathlib import Path

_TOOL_CACHE: dict[str, str | None] = {}
_TOOL_VECTOR_CACHE: dict[str, list[str] | None] = {}


def get_cmd_path(name: str) -> str | None:
    """Centralized tool discovery function for native Windows, Linux, and macOS.
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


def get_tool_executable_vector(name: str) -> list[str] | None:
    """Resolve the executable command vector for a tool.
    On native OS, returns [path_to_binary].
    On Windows when native binary is absent, seamlessly checks WSL and returns ['wsl', name].
    Returns None if tool is unavailable in all environments.
    """
    if name in _TOOL_VECTOR_CACHE:
        return _TOOL_VECTOR_CACHE[name]

    # 1. Native OS check
    native_path = get_cmd_path(name)
    if native_path:
        vector = [native_path]
        _TOOL_VECTOR_CACHE[name] = vector
        return vector

    # 2. Windows WSL fallback check
    if sys.platform == "win32" and shutil.which("wsl"):
        try:
            import subprocess
            res = subprocess.run(["wsl", "which", name], capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and res.stdout.strip():
                vector = ["wsl", name]
                _TOOL_VECTOR_CACHE[name] = vector
                return vector
        except Exception:
            pass

    _TOOL_VECTOR_CACHE[name] = None
    return None


def has_cmd(name: str) -> bool:
    """Return True if tool command is discoverable on system (Native or WSL)."""
    return get_tool_executable_vector(name) is not None


def get_tool_diagnostics(name: str) -> dict[str, Any]:
    """Retrieve diagnostic metadata regarding tool installation & availability."""
    vec = get_tool_executable_vector(name)
    if not vec:
        return {
            "tool": name,
            "available": False,
            "environment": "UNAVAILABLE",
            "command_vector": [],
            "message": f"Executable '{name}' not found on system PATH or WSL.",
        }

    is_wsl = (len(vec) > 1 and vec[0] == "wsl")
    return {
        "tool": name,
        "available": True,
        "environment": "WSL" if is_wsl else "NATIVE",
        "command_vector": vec,
        "resolved_path": vec[0] if not is_wsl else f"WSL:{vec[1]}",
    }
