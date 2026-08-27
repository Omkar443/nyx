"""
NYX Subfinder Tool Adapter
Specialized execution & output parsing adapter for Subfinder subdomain discovery.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Any
from nyx.execution.adapters.base import ToolAdapter
from nyx.execution.policy import extract_hostname
from nyx.infrastructure.tools import get_tool_executable_vector


class SubfinderAdapter(ToolAdapter):
    tool_name = "subfinder"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty domain string."

        clean_host = extract_hostname(target).strip().lower()
        if not clean_host:
            return False, "Target must be a non-empty domain string."

        # Check if clean_host is an IP address or localhost
        is_ip = False
        try:
            ipaddress.ip_address(clean_host)
            is_ip = True
        except ValueError:
            pass

        if is_ip or clean_host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return False, f"Target '{target}' is an IP address/local host and does not provide a valid domain enumeration scope."

        # Verify domain format (contains at least one dot, e.g. domain.com)
        if "." not in clean_host:
            return False, f"Target '{target}' is not a valid fully-qualified domain name (e.g. example.com)."

        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        clean_domain = extract_hostname(target).strip()
        tool_vec = get_tool_executable_vector("subfinder") or ["subfinder"]
        cmd = list(tool_vec) + ["-d", clean_domain]
        if arguments:
            # Filter out -u or redundant -d
            clean_args = []
            skip_next = False
            for a in arguments:
                if skip_next:
                    skip_next = False
                    continue
                if a in ("-u", "-d", "--target"):
                    skip_next = True
                    continue
                clean_args.append(a)
            if clean_args:
                cmd.extend(clean_args)
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
