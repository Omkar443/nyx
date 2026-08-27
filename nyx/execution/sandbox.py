"""
NYX Subprocess Sandbox & Environment Isolation
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def prepare_isolated_env(extra_env: dict | None = None) -> dict:
    env = os.environ.copy()
    # Enforce UTF-8, non-interactive execution, and module path
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PAGER"] = "cat"
    env["NONINTERACTIVE"] = "1"

    cur_pypath = env.get("PYTHONPATH", "")
    if str(REPO_ROOT) not in cur_pypath:
        env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{cur_pypath}" if cur_pypath else str(REPO_ROOT)

    if extra_env:
        env.update(extra_env)
    return env
