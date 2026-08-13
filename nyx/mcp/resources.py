"""
NYX Model Context Protocol (MCP) Resource Declarations
Declares NYX intelligence objects as MCP-compatible resources.
"""
from __future__ import annotations

from typing import Any, Dict, List

MCP_RESOURCES: List[Dict[str, Any]] = [
    {
        "uri": "engagement://target",
        "name": "Target Scope Configuration",
        "description": "Active target domain, authorized boundaries, and scope constraints.",
        "mimeType": "application/json",
    },
    {
        "uri": "engagement://endpoints",
        "name": "Endpoint Inventory",
        "description": "List of harvested URL endpoints and parameters.",
        "mimeType": "application/json",
    },
    {
        "uri": "engagement://technologies",
        "name": "Technology Inventory",
        "description": "Detected technology stack, frameworks, and servers.",
        "mimeType": "application/json",
    },
    {
        "uri": "engagement://findings",
        "name": "Findings Database",
        "description": "Vulnerability findings database and research state machine.",
        "mimeType": "application/json",
    },
]


def list_mcp_resources() -> List[Dict[str, Any]]:
    """Return registered MCP resource definitions."""
    return MCP_RESOURCES
