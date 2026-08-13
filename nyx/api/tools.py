"""
NYX Tool Registry & Policy Interface
"""
from __future__ import annotations
import yaml
from pathlib import Path
from nyx.infrastructure.filesystem import REPO_ROOT


def load_tools_registry(config_dir: Path | None = None) -> dict:
    c_dir = config_dir or (REPO_ROOT / ".nyx")
    t_file = c_dir / "tools.yaml"
    if not t_file.exists():
        return {}
    try:
        return yaml.safe_load(t_file.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def load_workflows(config_dir: Path | None = None) -> dict:
    c_dir = config_dir or (REPO_ROOT / ".nyx")
    w_file = c_dir / "workflows.yaml"
    if not w_file.exists():
        return {}
    try:
        return yaml.safe_load(w_file.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def load_policies(config_dir: Path | None = None) -> dict:
    c_dir = config_dir or (REPO_ROOT / ".nyx")
    p_file = c_dir / "policies.yaml"
    if not p_file.exists():
        return {}
    try:
        return yaml.safe_load(p_file.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
