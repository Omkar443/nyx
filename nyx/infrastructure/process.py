"""
NYX Infrastructure Command Execution Engine
"""
from __future__ import annotations
import subprocess
from nyx.infrastructure.tools import get_cmd_path


def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Execute command safely with timeout and path resolution."""
    if not cmd:
        return 1, "", "empty command"
    resolved_bin = get_cmd_path(cmd[0])
    exec_cmd = [resolved_bin] + cmd[1:] if resolved_bin else cmd
    try:
        p = subprocess.run(exec_cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
