# NYX Security Intelligence Engine - Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-08-13
### Initial Open Source Release
- **Core Intelligence Engine**: Consolidated state machine, scope authorization, evidence vault, and skill routing.
- **Execution Infrastructure**: Controlled tool sandbox, command policy, timeouts, and artifact normalization.
- **AI Agent Integration & MCP**: Provider abstraction (Gemini, NYX AI, GPT, Local LLMs), MCP tool/resource schemas, and AI policy enforcement.
- **Web Operations Platform**: FastAPI REST API, WebSocket live streaming, and React + TypeScript dashboard views.
- **Autonomous Multi-Agent Fleet**: Specialized research agents (`ReconAgent`, `WebAgent`, `APIAgent`, `TechnologyAgent`, `ValidationAgent`, `ReportingAgent`, `DynamicAgent`) with mandatory Human Approval Gates.
- **Distributed Worker Architecture**: HMAC mutual authentication, remote worker node dispatch, and SHA-256 evidence synchronization.
- **Browser & Runtime Intelligence**: Playwright session management, CDP-ready hooks, and Runtime Intelligence Graph constructor.
- **Continuous Security Intelligence**: Historical asset graph snapshots, automated surface change detection, alerting, research opportunity matching, and knowledge protection backups.
