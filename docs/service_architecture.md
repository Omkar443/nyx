# NYX Service Architecture

## Layer Responsibilities

### 1. Presentation Layer (`nyx.interface`)
- `nyx.interface.output`: Provides color formatting, section headers, and standard output abstraction (`color`, `say`, `section`).

### 2. Application Service Layer (`nyx.application`)
- Provides clean application service entrypoints for all security intelligence domain capabilities.
- `ReconService`: Coordinates target surface mapping and recon execution.
- `EngagementService`: Manages engagement lifecycle state, scopes, and target boundaries.
- `FindingService`: Manages finding state machine transitions and findings index synchronization.
- `EvidenceService`: Coordinates sanitization and canonical evidence vault storage.
- `AnalysisService`: Manages attack surface graphing and decision context generation.
- `ValidationService`: Coordinates triage, 7-Question Gate, and severity verification.
- `MissionService`: Orchestrates automated end-to-end bug hunting missions.
- `SkillService`: Manages skill index loading, skill routing, and parameter matching.

### 3. Core Domain Layer (`nyx.core`, `nyx.security`, `nyx.recon`, `nyx.validation`, `nyx.api`)
- Contains pure security research logic, rule evaluation, graph building, and validation checks.
- High cohesion and zero dependency on CLI parsing or terminal handling.

### 4. Infrastructure Layer (`nyx.infrastructure`)
- `filesystem.py`: Abstraction for filesystem operations, engagement directory discovery, and hash calculations.
- `tools.py`: Tool discovery and binary path resolution.
- `process.py`: Subprocess execution wrapper.
- `urls.py`: Canonical URL normalization and parsing.
