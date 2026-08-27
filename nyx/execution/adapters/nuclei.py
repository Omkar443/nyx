"""
NYX Nuclei Tool Adapter
Specialized execution & output parsing adapter for Nuclei vulnerability scanning.
"""
from __future__ import annotations

import json
from typing import Any
from nyx.execution.adapters.base import ToolAdapter
from nyx.infrastructure.tools import get_tool_executable_vector


class NucleiAdapter(ToolAdapter):
    tool_name = "nuclei"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty target URL or host."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        tool_vec = get_tool_executable_vector("nuclei") or ["nuclei"]
        cmd = list(tool_vec) + ["-u", target]
        if arguments:
            cmd.extend(arguments)
        else:
            cmd.extend(["-json"])
        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        findings = []
        for line in stdout.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("{"):
                try:
                    data = json.loads(line_str)
                    findings.append({
                        "template_id": data.get("template-id") or data.get("templateID"),
                        "name": data.get("info", {}).get("name") or data.get("name"),
                        "severity": data.get("info", {}).get("severity") or data.get("severity", "info"),
                        "matched_at": data.get("matched-at") or data.get("matched"),
                        "curl_command": data.get("curl-command"),
                    })
                except Exception:
                    pass

        return {
            "vulnerabilities": findings,
            "assets_found": len(findings),
            "count": len(findings),
            "parsed": True,
        }
