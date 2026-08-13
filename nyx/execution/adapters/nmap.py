"""
NYX Nmap Tool Adapter
Specialized execution & output parsing adapter for Nmap network & port scanning.
"""
from __future__ import annotations

import re
from typing import Any
from nyx.execution.adapters.base import ToolAdapter


class NmapAdapter(ToolAdapter):
    tool_name = "nmap"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty IP or hostname."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        cmd = ["nmap", target]
        if arguments:
            cmd.extend(arguments)
        else:
            cmd.extend(["-sV", "-T4"])
        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        ports = []
        port_re = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$")
        for line in stdout.splitlines():
            line_str = line.strip()
            match = port_re.match(line_str)
            if match:
                ports.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4).strip(),
                })

        return {
            "open_ports": ports,
            "assets_found": len(ports),
            "count": len(ports),
            "parsed": True,
        }
