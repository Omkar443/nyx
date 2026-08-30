"""
NYX Sqlmap Tool Adapter
Specialized execution and output parsing adapter for SQLMap automated SQL injection validation.
"""
from __future__ import annotations

from typing import Any
from nyx.execution.adapters.base import ToolAdapter
from nyx.infrastructure.tools import get_tool_executable_vector


class SqlmapAdapter(ToolAdapter):
    tool_name = "sqlmap"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty target URL or host."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        tool_vec = get_tool_executable_vector("sqlmap") or ["sqlmap"]
        cmd = list(tool_vec) + ["-u", target, "--batch"]
        if arguments:
            for arg in arguments:
                if arg not in cmd:
                    cmd.append(arg)
        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        findings = []
        is_vulnerable = False
        dbms = None
        technique = []

        for line in stdout.splitlines():
            line_clean = line.strip()
            if "is vulnerable" in line_clean.lower() or "sqlmap identified the following injection point" in line_clean.lower():
                is_vulnerable = True
            if "back-end DBMS:" in line_clean:
                dbms = line_clean.split("back-end DBMS:", 1)[-1].strip()
            if line_clean.startswith("Type:"):
                technique.append(line_clean.split("Type:", 1)[-1].strip())
            if line_clean.startswith("Title:"):
                findings.append({
                    "title": line_clean.split("Title:", 1)[-1].strip(),
                    "dbms": dbms,
                    "vulnerable": True,
                })

        if is_vulnerable and not findings:
            findings.append({
                "title": "SQL Injection Detected via SQLMap",
                "dbms": dbms,
                "vulnerable": True,
            })

        return {
            "vulnerabilities": findings,
            "is_vulnerable": is_vulnerable or len(findings) > 0,
            "dbms": dbms,
            "techniques": technique,
            "assets_found": len(findings),
            "count": len(findings),
            "parsed": True,
            "tool": "sqlmap",
        }
