"""
NYX Model Context Protocol (MCP) Tools Definition
Declares NYX capability tools as MCP-compatible objects.
"""
from __future__ import annotations

from typing import Any, Dict, List
from nyx.mcp.schemas import (
    RECON_TARGET_SCHEMA,
    EXECUTE_TOOL_SCHEMA,
    CLASSIFY_URL_SCHEMA,
    TRIAGE_FINDING_SCHEMA,
    GENERATE_REPORT_SCHEMA,
)

MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "recon_target",
        "description": "Perform authorized passive reconnaissance and attack surface discovery.",
        "input_schema": RECON_TARGET_SCHEMA,
    },
    {
        "name": "execute_tool",
        "description": "Execute a controlled security tool through NYX execution engine.",
        "input_schema": EXECUTE_TOOL_SCHEMA,
    },
    {
        "name": "classify_endpoint",
        "description": "Classify target endpoint and match to specialized security research skills.",
        "input_schema": CLASSIFY_URL_SCHEMA,
    },
    {
        "name": "triage_finding",
        "description": "Run the 7-Question Gate and duplicate checks on a finding hypothesis.",
        "input_schema": TRIAGE_FINDING_SCHEMA,
    },
    {
        "name": "generate_report",
        "description": "Generate platform-formatted security report from verified finding.",
        "input_schema": GENERATE_REPORT_SCHEMA,
    },
]


def list_mcp_tools() -> List[Dict[str, Any]]:
    """Return registered MCP tool definitions."""
    return MCP_TOOLS
