"""
NYX Native Security Probe Tool Adapter
Specialized execution & output parsing adapter for automated HTTP vulnerability probing.
"""
from __future__ import annotations

import json
import sys
from typing import Any
from nyx.execution.adapters.base import ToolAdapter


class ProbeAdapter(ToolAdapter):
    tool_name = "probe"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty URL or host."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        cmd = [sys.executable, "-m", "nyx.execution.adapters.probe_runner", target]
        if arguments:
            cmd.extend(arguments)
        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        findings = []
        parsed = False

        for line in stdout.splitlines():
            line_str = line.strip()
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    data = json.loads(line_str)
                    if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                        findings.extend(data["vulnerabilities"])
                        parsed = True
                    elif "vulnerability" in data or "finding_candidate" in data:
                        cand = data.get("finding_candidate", data)
                        findings.append(cand)
                        parsed = True
                except Exception:
                    pass

        return {
            "vulnerabilities": findings,
            "count": len(findings),
            "parsed": parsed,
        }
