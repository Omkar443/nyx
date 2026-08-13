"""
NYX Timeout & Subprocess Execution Layer
"""
from __future__ import annotations
import os
import subprocess
import time
from pathlib import Path


def run_with_timeout(cmd_list: list[str], timeout_sec: int = 60, cwd: Path | str | None = None, env: dict | None = None) -> tuple[int, str, str, bool]:
    """Execute command vector in a controlled subprocess with strict timeout enforcement.
    Returns (exit_code, stdout, stderr, timed_out)."""
    env_vars = env or os.environ.copy()

    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=env_vars
        )

        try:
            stdout, stderr = proc.communicate(timeout=timeout_sec)
            return proc.returncode, stdout or "", stderr or "", False
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return -1, stdout or "", f"Command execution timed out after {timeout_sec} seconds.", True
    except Exception as e:
        return 1, "", str(e), False
