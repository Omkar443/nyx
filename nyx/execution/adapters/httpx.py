"""
NYX Httpx Tool Adapter
Specialized execution & output parsing adapter for httpx live host probing & technology detection.
"""
from __future__ import annotations

import json
from typing import Any
from nyx.execution.adapters.base import ToolAdapter


class HttpxAdapter(ToolAdapter):
    tool_name = "httpx"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty target domain or URL."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        cmd = ["httpx", "-u", target]
        if arguments:
            cmd.extend(arguments)
        else:
            cmd.extend(["-status-code", "-title", "-tech-detect", "-json"])
        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        hosts = []
        technologies = set()
        for line in stdout.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("{"):
                try:
                    data = json.loads(line_str)
                    url = data.get("url") or data.get("input")
                    code = data.get("status_code") or data.get("status-code")
                    title = data.get("title", "")
                    techs = data.get("tech") or data.get("technologies") or []
                    if isinstance(techs, list):
                        for t in techs:
                            technologies.add(str(t))

                    hosts.append({
                        "url": url,
                        "status": code,
                        "title": title,
                        "technologies": techs,
                    })
                except Exception:
                    pass
            else:
                hosts.append({"url": line_str, "status": 200, "title": "", "technologies": []})

        return {
            "live_hosts": hosts,
            "assets_found": len(hosts),
            "count": len(hosts),
            "technologies": sorted(technologies),
            "parsed": True,
        }
