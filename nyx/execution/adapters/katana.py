"""
NYX Katana Tool Adapter
Specialized execution & output parsing adapter for Katana web crawling & endpoint discovery.
"""
from __future__ import annotations

import json
from typing import Any
from nyx.execution.adapters.base import ToolAdapter
from nyx.infrastructure.tools import get_tool_executable_vector


class KatanaAdapter(ToolAdapter):
    tool_name = "katana"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty target URL."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        tool_vec = get_tool_executable_vector("katana") or ["katana"]
        cmd = list(tool_vec) + ["-u", target]
        if arguments:
            cmd.extend(arguments)
        else:
            cmd.extend(["-jc", "-kf", "all", "-j"])
        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        endpoints = set()
        for line in stdout.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("{"):
                try:
                    data = json.loads(line_str)
                    ep = data.get("endpoint") or data.get("url") or data.get("request", {}).get("endpoint")
                    if ep:
                        endpoints.add(ep)
                except Exception:
                    pass
            else:
                endpoints.add(line_str)

        sorted_eps = sorted(endpoints)
        return {
            "endpoints": sorted_eps,
            "assets_found": len(sorted_eps),
            "count": len(sorted_eps),
            "parsed": True,
        }
