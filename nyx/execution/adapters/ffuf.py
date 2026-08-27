"""
NYX FFUF Tool Adapter
Specialized execution and output parsing adapter for FFUF web directory and content discovery.
"""
from __future__ import annotations

import json
from typing import Any
from nyx.execution.adapters.base import ToolAdapter
from nyx.infrastructure.tools import get_tool_executable_vector


class FfufAdapter(ToolAdapter):
    tool_name = "ffuf"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty target URL."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        target_url = target.rstrip("/")
        if "FUZZ" not in target_url:
            target_url = f"{target_url}/FUZZ"

        tool_vec = get_tool_executable_vector("ffuf") or ["ffuf"]
        cmd = list(tool_vec) + ["-u", target_url, "-json", "-mc", "200,204,301,302,307,401,403"]
        if arguments:
            cmd.extend(arguments)
        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        endpoints = []
        parsed = False
        try:
            data = json.loads(stdout)
            for res in data.get("results", []):
                ep = res.get("url")
                if ep:
                    endpoints.append({
                        "url": ep,
                        "status": res.get("status"),
                        "length": res.get("length"),
                        "words": res.get("words"),
                        "lines": res.get("lines"),
                        "source": "content_discovery"
                    })
            parsed = True
        except Exception:
            for line in stdout.splitlines():
                line_str = line.strip()
                if line_str.startswith("{"):
                    try:
                        res = json.loads(line_str)
                        ep = res.get("url")
                        if ep:
                            endpoints.append({
                                "url": ep,
                                "status": res.get("status"),
                                "source": "content_discovery"
                            })
                            parsed = True
                    except Exception:
                        pass

        ep_urls = [e["url"] if isinstance(e, dict) else e for e in endpoints]
        return {
            "endpoints": sorted(list(set(ep_urls))),
            "results": endpoints,
            "count": len(endpoints),
            "assets_found": len(endpoints),
            "parsed": parsed,
        }
