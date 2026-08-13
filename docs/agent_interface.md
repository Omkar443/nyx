# NYX Agent API Interface Specification

## 1. Overview
The `nyx.api.agent` module provides structured programmatic functions for external AI agents (Google Antigravity, NYX AI, GPT, Gemini, and MCP clients).

---

## 2. API Endpoint Functions

### `get_target_context(target: str) -> dict`
Retrieves aggregated engagement target scope, active state phase, detected technologies, harvested endpoints, matched skills, and previous failed approaches.

### `list_skills(category: str | None = None) -> dict`
Lists available NYX security research skills catalog formatted as a structured dictionary result container.

### `run_recon(target: str) -> dict`
Triggers authorized passive reconnaissance surface discovery.

### `execute_tool(tool_name: str, target: str, arguments: list[str] | None = None, dry_run: bool = False) -> dict`
Executes a controlled security tool through the execution engine.

### `validate_finding(finding_id: str) -> dict`
Queries a finding hypothesis against empirical verification rules.

### `generate_report(finding_id: str, platform: str = "bugcrowd") -> dict`
Generates platform-formatted security research report.

### `plan_mission(target: str, provider_name: str | None = None) -> dict`
Generates a policy-validated, multi-step mission plan using AI provider reasoning.
