"""
NYX Security Intelligence Engine Main API Exports
"""
import os
from pathlib import Path

# Automatically populate environment from local .env if not already set
_env_file = Path.cwd() / ".env"
if _env_file.exists():
    try:
        for line in _env_file.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                k_clean = k.strip()
                if k_clean not in os.environ:
                    os.environ[k_clean] = v.strip().strip("'").strip('"')
    except Exception:
        pass

from nyx.core import recon, engagement, findings, evidence, analysis, knowledge, router, surface
from nyx.api import mission, tools

__all__ = ["recon", "engagement", "findings", "evidence", "analysis", "knowledge", "router", "surface", "mission", "tools"]
