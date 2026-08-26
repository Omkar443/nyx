"""
NYX Command Builder & Validation Layer
"""
from __future__ import annotations
import shlex
from pathlib import Path
from nyx.infrastructure.tools import get_cmd_path, has_cmd
from nyx.api.tools import load_tools_registry


def build_command(tool_name: str, target: str, extra_args: list[str] | None = None) -> tuple[bool, str, list[str]]:
    """Build and validate executable command vector for target tool.
    Returns (valid, error_msg, cmd_list)."""
    tools_reg = load_tools_registry().get("tools", {})
    t_config = tools_reg.get(tool_name.lower())

    if not t_config:
        # Check standard binary discovery
        cmd_path = get_cmd_path(tool_name)
        if not cmd_path:
            return False, f"Tool '{tool_name}' not found in registry or PATH.", []
        cmd_list = [cmd_path, target]
        if extra_args:
            cmd_list.extend(extra_args)
        return True, "", cmd_list

    binary = t_config.get("binary", tool_name)
    cmd_path = get_cmd_path(binary)
    if not cmd_path:
        return False, f"Binary '{binary}' for tool '{tool_name}' is not installed or discoverable.", []

    cmd_list = [cmd_path]
    allowed_args = t_config.get("allowed_args", [])

    # Target argument placement
    if tool_name.lower() == "subfinder":
        cmd_list.extend(["-d", target, "-silent"])
    elif tool_name.lower() == "httpx":
        from nyx.execution.adapters.httpx import is_python_httpx_cli
        if is_python_httpx_cli():
            target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
            cmd_list.append(target_url)
        else:
            cmd_list.extend(["-u", target, "-silent"])
    elif tool_name.lower() == "katana":
        cmd_list.extend(["-u", target, "-silent"])
    elif tool_name.lower() == "nuclei":
        cmd_list.extend(["-target", target, "-silent"])
    elif tool_name.lower() == "curl":
        cmd_list.extend(["-s", "-i", target])
    else:
        cmd_list.append(target)

    if extra_args:
        for arg in extra_args:
            # Validate allowed args if configured
            if allowed_args:
                base_flag = arg.split("=")[0]
                if base_flag not in allowed_args and arg not in allowed_args:
                    return False, f"Argument '{arg}' is not in allowed_args list for tool '{tool_name}'.", []
            cmd_list.append(arg)

    return True, "", cmd_list
