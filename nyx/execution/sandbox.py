"""
NYX Subprocess Sandbox & Environment Isolation
"""
from __future__ import annotations
import os


def prepare_isolated_env(extra_env: dict | None = None) -> dict:
    env = os.environ.copy()
    # Enforce UTF-8 and non-interactive execution
    env["PYTHONIOENCODING"] = "utf-8"
    env["PAGER"] = "cat"
    env["NONINTERACTIVE"] = "1"
    if extra_env:
        env.update(extra_env)
    return env
