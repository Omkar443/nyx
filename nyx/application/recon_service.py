"""
NYX Recon Application Service
Orchestrates passive recon, subdomain discovery, DNS resolution, and HTTP probing.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from nyx.core import recon as core_recon
from nyx.infrastructure.filesystem import _get_eng_dir


class ReconService:
    """Service facade for recon execution and memory synchronization."""

    def run_recon(
        self,
        target: str,
        out_dir: str | Path | None = None,
        proxy: str | None = None,
        burp: bool = False,
    ) -> dict[str, Any]:
        return core_recon.run_recon(
            target=target, out_dir=out_dir, proxy=proxy, burp=burp
        )

    def sync_to_engagement(
        self, target: str, subs: set, resolved: dict, live: list
    ) -> tuple[int, int, int]:
        return core_recon.sync_recon_to_engagement(target, subs, resolved, live)

    def run_intelligence(self, target: str) -> dict[str, Any]:
        return core_recon.run_intelligence(target)

    def get_endpoints(self) -> dict[str, Any]:
        """Retrieve harvested endpoints from engagement memory."""
        d = _get_eng_dir()
        ep_file = d / "endpoints.json"
        endpoints = []
        if ep_file.exists():
            try:
                endpoints = json.loads(ep_file.read_text(encoding="utf-8"))
            except Exception:
                endpoints = []
        return {"success": True, "endpoints": endpoints, "count": len(endpoints)}

    def get_technologies(self) -> dict[str, Any]:
        """Retrieve detected technologies from engagement memory."""
        d = _get_eng_dir()
        tech_file = d / "technologies.json"
        technologies = []
        if tech_file.exists():
            try:
                technologies = json.loads(tech_file.read_text(encoding="utf-8"))
            except Exception:
                technologies = []
        return {"success": True, "technologies": technologies, "count": len(technologies)}
