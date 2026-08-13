# NYX Core Decoupling Audit Report

> [!NOTE]
> This document describes internal development history before NYX identity migration.
> It is archived and not part of the public architecture documentation.


> [!NOTE]
> **Historical Migration Reference**
> This document describes previous internal architecture migration.
> It is preserved for engineering history only. Current project identity is NYX.


## Architectural Overview & Objectives
Phase 11 decoupling migrated the NYX Security Intelligence Engine from a tightly coupled architecture relying directly on `nyx_cli.cli` to a layered enterprise service architecture.

```
       CLI Adapter Layer (nyx_cli/cli.py)
                    │
                    ▼
     NYX Application Services (nyx/application/*)
                    │
                    ▼
       NYX Core Engines (nyx/core/*)
         ├── nyx/security/*
         ├── nyx/recon/*
         ├── nyx/validation/*
         └── nyx/models/*
                    │
                    ▼
   NYX Infrastructure Layer (nyx/infrastructure/*)
         ├── filesystem.py
         ├── tools.py
         ├── process.py
         └── urls.py
```

## Inventory of Decoupled Modules

### 1. Presentation Layer (`nyx/interface/output.py`)
- Extracted terminal output formatting functions: `color()`, `say()`, `section()`.

### 2. Infrastructure Layer (`nyx/infrastructure/`)
- `filesystem.py`: Extracted `REPO_ROOT`, `_get_eng_dir()`, `calculate_file_hash()`.
- `tools.py`: Extracted centralized tool discovery helpers `get_cmd_path()`, `has_cmd()`.
- `process.py`: Extracted command execution wrapper `run_cmd()`.
- `urls.py`: Extracted URL normalization `normalize_url()`.

### 3. Security Layer (`nyx/security/`)
- `authorization.py`: Extracted authorization checks (`check_authorization`), scope verification (`get_engagement_scope`, `is_hostname_in_scope`), and canonical evidence sanitization (`sanitize_canonical_evidence`, `SanitizationResult`).
- `scope.py`: Re-exports domain scope verification policies.

### 4. Application Service Layer (`nyx/application/`)
Created thin orchestration facades:
- `recon_service.py`: `ReconService`
- `engagement_service.py`: `EngagementService`
- `finding_service.py`: `FindingService`
- `evidence_service.py`: `EvidenceService`
- `analysis_service.py`: `AnalysisService`
- `validation_service.py`: `ValidationService`
- `mission_service.py`: `MissionService`
- `skill_service.py`: `SkillService`

## Coupling Reduction Metrics
- **Initial direct coupling**: 20 `nyx` modules directly importing `nyx_cli.cli`.
- **Final direct `nyx/core` coupling**: 0 direct imports.
- **Total `nyx` package imports from `nyx_cli.cli`**: 5 (strictly contained within `nyx/application/*_service.py` adapters).

## Verification & Regression Status
- All 12 regression test suites (`scratch/stage3_tests.py` through `scratch/phase110_tests.py`) passed cleanly.
- `python -m build` successfully packages all `nyx` subpackages into `nyx_security_engine-1.0.0-py3-none-any.whl`.
