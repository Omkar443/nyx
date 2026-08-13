"""
NYX Model Context Protocol (MCP) Schemas
Defines standard JSON schemas for MCP tools and resources.
"""
from __future__ import annotations

RECON_TARGET_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "Target root domain or URL"},
        "subcommand": {"type": "string", "enum": ["intelligence", "js", "api", "parameters"]},
    },
    "required": ["target"],
}

EXECUTE_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "tool_name": {"type": "string", "description": "Security tool binary name (subfinder, httpx, katana, nuclei, nmap)"},
        "target": {"type": "string", "description": "Target host or URL"},
        "arguments": {"type": "array", "items": {"type": "string"}},
        "dry_run": {"type": "boolean", "default": False},
    },
    "required": ["tool_name", "target"],
}

CLASSIFY_URL_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target endpoint URL to classify and match skills"},
    },
    "required": ["url"],
}

TRIAGE_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_file": {"type": "string", "description": "Path to finding markdown file"},
    },
    "required": ["finding_file"],
}

GENERATE_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string", "description": "Finding ID (FH-YYYY-XXX)"},
        "platform": {"type": "string", "enum": ["bugcrowd", "hackerone", "intigriti", "markdown"]},
    },
    "required": ["finding_id"],
}
