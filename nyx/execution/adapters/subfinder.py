"""
NYX Subfinder Tool Adapter
Specialized execution & output parsing adapter for Subfinder subdomain discovery.
"""
from __future__ import annotations

import json
from typing import Any
from nyx.execution.adapters.base import ToolAdapter


class SubfinderAdapter(ToolAdapter):
    tool_name = "subfinder"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty domain string."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        cmd = ["subfinder", "-d", target]
        if arguments:
            cmd.extend(arguments)
        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        subdomains = set()
        for line in stdout.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("["):
                continue
            if line_str.startswith("{"):
                try:
                    data = json.loads(line_str)
                    host = data.get("host") or data.get("subdomain")
                    if host:
                        subdomains.add(host.lower().strip())
                except Exception:
                    pass
            else:
                subdomains.add(line_str.lower())

        sorted_subs = sorted(subdomains)
        return {
            "subdomains": sorted_subs,
            "assets_found": len(sorted_subs),
            "count": len(sorted_subs),
            "parsed": True,
        }
