"""
NYX Httpx Tool Adapter
Specialized execution & output parsing adapter for httpx live host probing & technology detection.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any
from nyx.execution.adapters.base import ToolAdapter

_IS_PYTHON_HTTPX: bool | None = None


def is_python_httpx_cli() -> bool:
    """Detect if the installed httpx binary in PATH is Python's httpx CLI or ProjectDiscovery's Go httpx."""
    global _IS_PYTHON_HTTPX
    if _IS_PYTHON_HTTPX is not None:
        return _IS_PYTHON_HTTPX

    httpx_path = shutil.which("httpx")
    if not httpx_path:
        _IS_PYTHON_HTTPX = False
        return False

    # Check path heuristics
    path_lower = httpx_path.lower()
    if "python" in path_lower and ("scripts" in path_lower or "site-packages" in path_lower):
        _IS_PYTHON_HTTPX = True
        return True

    import os
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    try:
        res = subprocess.run([httpx_path, "--help"], capture_output=True, text=True, timeout=3, env=env)
        out = (res.stdout or "") + (res.stderr or "")
        if "HTTPX" in out and "-u" not in out:
            _IS_PYTHON_HTTPX = True
        else:
            _IS_PYTHON_HTTPX = False
    except Exception:
        _IS_PYTHON_HTTPX = False
    return _IS_PYTHON_HTTPX


class HttpxAdapter(ToolAdapter):
    tool_name = "httpx"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty target domain or URL."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        target_url = target
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target}"

        if is_python_httpx_cli():
            cmd = ["httpx"]
            url_in_args = None
            filtered_args = []
            if arguments:
                # Exclude ProjectDiscovery specific flags that cause errors on Python httpx CLI
                pd_flags = {"-status-code", "-title", "-tech-detect", "-json", "-u"}
                for a in arguments:
                    if a.startswith("http://") or a.startswith("https://"):
                        url_in_args = a
                    elif a not in pd_flags:
                        filtered_args.append(a)
                cmd.extend(filtered_args)
            final_url = url_in_args or target_url
            cmd.append(final_url)
            return cmd
        else:
            cmd = ["httpx", "-u", target]
            if arguments:
                cmd.extend(arguments)
            else:
                cmd.extend(["-status-code", "-title", "-tech-detect", "-json"])
            return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        hosts = []
        technologies = set()

        def _extract_host(data: dict) -> None:
            if not isinstance(data, dict):
                return
            url = data.get("url") or data.get("input")
            if not url:
                return
            code = data.get("status_code") or data.get("status-code")
            title = data.get("title", "")
            server = data.get("webserver") or data.get("server", "")
            host = data.get("host")
            techs = data.get("tech") or data.get("technologies") or []
            if isinstance(techs, list):
                for t in techs:
                    technologies.add(str(t))

            entry = {
                "url": url,
                "status": code,
                "title": title,
                "technologies": techs,
            }
            if server:
                entry["server"] = server
                entry["webserver"] = server
            if host:
                entry["host"] = host
            hosts.append(entry)

        raw = (stdout or "").strip()
        parsed_as_single = False

        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    _extract_host(data)
                    parsed_as_single = True
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            _extract_host(item)
                    parsed_as_single = True
            except (json.JSONDecodeError, Exception):
                parsed_as_single = False

        if not parsed_as_single:
            for line in (stdout or "").splitlines():
                line_str = line.strip()
                if not line_str or not line_str.startswith("{"):
                    continue
                try:
                    data = json.loads(line_str)
                    if isinstance(data, dict):
                        _extract_host(data)
                        parsed_as_single = True
                except Exception:
                    pass

        # Parse plain HTTP response format (e.g. Python httpx CLI output)
        if not hosts and ("HTTP/1." in raw or "HTTP/2" in raw or "Server:" in raw):
            status_match = re.search(r"HTTP/[0-9.]+\s+(\d{3})", raw)
            status_code = int(status_match.group(1)) if status_match else 200

            server_match = re.search(r"^Server:\s*(.+)$", raw, re.M | re.I)
            server = server_match.group(1).strip() if server_match else ""
            if server:
                technologies.add(server.split("/")[0].strip())

            powered_match = re.search(r"^X-Powered-By:\s*(.+)$", raw, re.M | re.I)
            powered = powered_match.group(1).strip() if powered_match else ""
            if powered:
                technologies.add(powered.split("/")[0].strip())

            title_match = re.search(r"<title>(.*?)</title>", raw, re.I | re.S)
            title = title_match.group(1).strip() if title_match else ""

            hosts.append({
                "url": "target",
                "status": status_code,
                "title": title,
                "server": server,
                "technologies": sorted(technologies),
            })

        is_empty_stdout = (raw == "")
        is_parsed = not (not hosts and is_empty_stdout)

        result: dict[str, Any] = {
            "live_hosts": hosts,
            "assets_found": len(hosts),
            "count": len(hosts),
            "technologies": sorted(technologies),
            "parsed": is_parsed,
        }
        if not hosts and is_empty_stdout:
            result["warning"] = (
                "No output received from httpx — the target may be unreachable, "
                "timed out internally, or blocked the request. Exit code was 0 but no host data was returned."
            )

        return result
