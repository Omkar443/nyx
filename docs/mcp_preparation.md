# NYX Model Context Protocol (MCP) Preparation Layer

## 1. Overview
The `nyx.mcp` sub-package prepares NYX capabilities as standardized Model Context Protocol (MCP) objects. This allows AI clients (e.g. NYX AI Desktop, Antigravity IDE) to discover NYX capabilities as native MCP tools and resources in future phases.

---

## 2. Prepared MCP Tools (`nyx/mcp/tools.py`)

- `recon_target`: Authorized passive reconnaissance tool.
- `execute_tool`: Controlled security tool execution tool.
- `classify_endpoint`: Endpoint classification and skill matching tool.
- `triage_finding`: 7-Question Gate and duplicate finding verification tool.
- `generate_report`: Security report generation tool.

---

## 3. Prepared MCP Resources (`nyx/mcp/resources.py`)

- `engagement://target`: Target scope configuration resource.
- `engagement://endpoints`: Endpoint inventory resource.
- `engagement://technologies`: Technology inventory resource.
- `engagement://findings`: Findings database resource.
