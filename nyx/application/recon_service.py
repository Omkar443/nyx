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

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir

    def run_recon(
        self,
        target: str,
        out_dir: str | Path | None = None,
        proxy: str | None = None,
        burp: bool = False,
    ) -> dict[str, Any]:
        res = core_recon.run_recon(
            target=target, out_dir=out_dir, proxy=proxy, burp=burp, base_dir=self.base_dir
        )
        is_ok = res.get("status") == "success"
        endpoints_count = res.get("sync_total") or (res.get("content_discovery_count", 0) + res.get("live_count", 0))
        return {
            "success": is_ok,
            "data": {
                **res,
                "endpoints_count": endpoints_count,
            },
            "endpoints_count": endpoints_count,
            "error": None if is_ok else res.get("message", "Recon error"),
            "code": "OK" if is_ok else "RECON_ERROR"
        }

    def sync_to_engagement(
        self, target: str, subs: set, resolved: dict, live: list
    ) -> tuple[int, int, int]:
        return core_recon.sync_recon_to_engagement(target, subs, resolved, live)

    def run_intelligence(self, target: str) -> dict[str, Any]:
        return core_recon.run_intelligence(target)

    def get_endpoints(self, target: str | None = None) -> dict[str, Any]:
        """Retrieve harvested endpoints from engagement memory, optionally filtered by target."""
        from nyx.core.engagement import get_engagement_target
        from nyx.ai.context import _matches_target_endpoint

        d = _get_eng_dir(base_dir=self.base_dir)
        ep_file = d / "endpoints.json"
        endpoints = []
        if ep_file.exists():
            try:
                endpoints = json.loads(ep_file.read_text(encoding="utf-8"))
            except Exception:
                endpoints = []

        effective_target = target if target is not None else get_engagement_target(base_dir=self.base_dir)
        if effective_target and effective_target not in ("*", "all") and endpoints:
            endpoints = [
                ep for ep in endpoints
                if _matches_target_endpoint(ep.get("url", "") if isinstance(ep, dict) else str(ep), effective_target)
                or (isinstance(ep, dict) and ep.get("target") and _matches_target_endpoint(ep.get("target"), effective_target))
            ]

        return {"success": True, "endpoints": endpoints, "count": len(endpoints)}

    def get_technologies(self, target: str | None = None) -> dict[str, Any]:
        """Retrieve detected technologies from engagement memory."""
        d = _get_eng_dir(base_dir=self.base_dir)
        tech_file = d / "technologies.json"
        raw_tech = {}
        if tech_file.exists():
            try:
                raw_tech = json.loads(tech_file.read_text(encoding="utf-8"))
            except Exception:
                raw_tech = {}

        flat_list: list[str] = []
        if isinstance(raw_tech, dict):
            for v in raw_tech.values():
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and item.strip():
                            flat_list.append(item.strip())
                        elif isinstance(item, dict) and item.get("name"):
                            flat_list.append(str(item["name"]).strip())
                elif isinstance(v, str) and v.strip():
                    flat_list.append(v.strip())
            flat_list = sorted(list(set(flat_list)))
        elif isinstance(raw_tech, list):
            for item in raw_tech:
                if isinstance(item, str) and item.strip():
                    flat_list.append(item.strip())
                elif isinstance(item, dict) and item.get("name"):
                    flat_list.append(str(item["name"]).strip())
            flat_list = sorted(list(set(flat_list)))

        return {
            "success": True,
            "technologies": flat_list,
            "count": len(flat_list),
            "categories": raw_tech if isinstance(raw_tech, dict) else {},
        }
