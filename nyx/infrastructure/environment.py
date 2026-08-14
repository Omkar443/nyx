"""
NYX Infrastructure Environment Detection & Platform Audit
"""
from __future__ import annotations

import os
import sys
import socket
import shutil
import platform
try:
    import fcntl  # type: ignore
except ImportError:
    fcntl = None

from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class DependencyProfile(str, Enum):
    CORE = "CORE"
    WEB = "WEB"
    TEST = "TEST"
    DEVELOPMENT = "DEVELOPMENT"


class PlatformInfo:
    """System platform, executable, and package manager detector."""

    @staticmethod
    def get_os() -> str:
        if sys.platform == "win32":
            return "windows"
        if sys.platform == "darwin":
            return "darwin"
        if sys.platform.startswith("linux"):
            try:
                proc_ver = Path("/proc/version")
                if proc_ver.exists() and ("microsoft" in proc_ver.read_text().lower() or "wsl" in proc_ver.read_text().lower()):
                    return "wsl2"
                os_rel = Path("/proc/sys/kernel/osrelease")
                if os_rel.exists() and ("microsoft" in os_rel.read_text().lower() or "wsl" in os_rel.read_text().lower()):
                    return "wsl2"
            except Exception:
                pass
            return "linux"
        return sys.platform

    @staticmethod
    def is_wsl2() -> bool:
        return PlatformInfo.get_os() == "wsl2"

    @staticmethod
    def get_python_cmd() -> str:
        return sys.executable or ("python3" if shutil.which("python3") else "python")

    @staticmethod
    def get_python_version() -> str:
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    @staticmethod
    def is_python_valid(min_version: tuple[int, int] = (3, 9)) -> bool:
        return sys.version_info >= min_version

    @staticmethod
    def detect_package_managers() -> List[str]:
        pms = []
        for pm in ["apt", "apt-get", "winget", "choco", "brew", "dnf", "yum", "pacman"]:
            if shutil.which(pm):
                pms.append(pm)
        return pms

    @staticmethod
    def check_internet(host: str = "1.1.1.1", port: int = 53, timeout_sec: float = 2.0) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_sec)
            sock.connect((host, port))
            sock.close()
            return True
        except Exception:
            return False


class BootstrapLock:
    """Cross-process file lock preventing concurrent dependency installation races."""

    def __init__(self, lock_file: Optional[Path] = None):
        if lock_file:
            self.lock_file = lock_file
        else:
            nyx_dir = Path.cwd() / ".nyx"
            nyx_dir.mkdir(parents=True, exist_ok=True)
            self.lock_file = nyx_dir / ".bootstrap.lock"
        self._fd: Optional[Any] = None

    def __enter__(self):
        try:
            self.lock_file.parent.mkdir(parents=True, exist_ok=True)
            self._fd = open(self.lock_file, "w")
            if fcntl and hasattr(fcntl, "flock"):
                fcntl.flock(self._fd, fcntl.LOCK_EX)
        except Exception:
            pass
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self._fd:
                if fcntl and hasattr(fcntl, "flock"):
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
                self._fd.close()
                self._fd = None
        except Exception:
            pass


def print_preflight_banner(checks: List[Dict[str, Any]], profile_name: str = "WEB") -> None:
    """Render preflight check output banner."""
    lines = []
    lines.append(f"\nNYX Environment Preflight Check [{profile_name}]")
    lines.append("─" * 48)
    for c in checks:
        name = c.get("name", "")
        status = c.get("status", "FAIL")
        icon = "✓" if status in ("OK", "PASS") else ("⚠" if status == "WARN" else "✗")
        detail = c.get("detail", "")
        detail_str = f" ({detail})" if detail else ""
        lines.append(f"  {name:<22} {icon} {status}{detail_str}")
    lines.append("─" * 48)
    print("\n".join(lines))
