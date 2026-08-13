# Phase 12 — NYX CLI Decoupling Audit Report

> [!NOTE]
> This document describes internal development history before NYX identity migration.
> It is archived and not part of the public architecture documentation.


> [!NOTE]
> **Historical Migration Reference**: This document describes historical architectural migrations and baseline decoupling iterations.


## 1. Executive Summary & Codebase Metrics
This audit maps the coupling and business logic distribution between `nyx_cli/cli.py` and the `nyx/` package prior to Phase 12 extraction.

- **`nyx_cli/cli.py` Total Line Count**: 3,380 lines
- **Total Functions in `nyx_cli/cli.py`**: 74 functions
- **Total `cmd_*` Handlers**: 19 handlers:
  - `cmd_analyze`
  - `cmd_classify`
  - `cmd_duplicate_check`
  - `cmd_engagement`
  - `cmd_evidence`
  - `cmd_exec`
  - `cmd_finding`
  - `cmd_findings`
  - `cmd_knowledge`
  - `cmd_memory`
  - `cmd_mission`
  - `cmd_recon`
  - `cmd_report`
  - `cmd_skills`
  - `cmd_state`
  - `cmd_surface`
  - `cmd_technology_map`
  - `cmd_triage`
  - `cmd_validate`

---

## 2. Command Backing Breakdown

| Command Family | Handler Name | Current Backing Implementation | Target Application Service |
|---|---|---|---|
| Engagement | `cmd_engagement`, `cmd_state`, `cmd_memory` | Legacy logic inside `nyx_cli/cli.py` | `EngagementService` |
| Recon | `cmd_recon` | Passive recon & tool runner inside `nyx_cli/cli.py` | `ReconService` |
| Findings | `cmd_finding`, `cmd_findings`, `cmd_duplicate_check` | State machine & index sync inside `nyx_cli/cli.py` | `FindingService` |
| Evidence | `cmd_evidence` | Vault management & hashing inside `nyx_cli/cli.py` | `EvidenceService` |
| Analysis | `cmd_analyze`, `cmd_classify`, `cmd_surface`, `cmd_technology_map` | Surface graph & tech map in `nyx_cli/cli.py` | `AnalysisService` |
| Validation | `cmd_validate`, `cmd_triage` | Triage & rules in `nyx_cli/cli.py` | `ValidationService` |
| Mission | `cmd_mission` | Delegates to `nyx.api.mission` | `MissionService` |
| Skills | `cmd_skills` | Delegates to `nyx.core.skills` | `SkillService` |
| Knowledge | `cmd_knowledge` | Knowledge search in `nyx_cli/cli.py` | `SkillService` / `nyx.core.knowledge` |
| Doctor | `main` doctor flow | Utility check in `nyx_cli/cli.py` | `Infrastructure` / `EngagementService` |

---

## 3. Remaining `nyx_cli.cli` Imports Across Repository
Currently, only 5 service facades import `nyx_cli.cli`:
- `nyx/application/recon_service.py`
- `nyx/application/engagement_service.py`
- `nyx/application/finding_service.py`
- `nyx/application/evidence_service.py`
- `nyx/application/analysis_service.py`

In addition, scratch test scripts import symbols from `nyx_cli.cli`. Once business logic is canonicalized into `nyx/core` and `nyx/application`, `nyx/application` will have **0 imports** from `nyx_cli.cli`.

---

## 4. Circular Dependency Risk Analysis
Currently, `nyx/application` imports `nyx_cli.cli` to execute command handlers, while `nyx_cli.cli` imports `nyx` modules (`nyx.core`, `nyx.security`, `nyx.infrastructure`, `nyx.interface`). Moving the business logic into `nyx.core` / `nyx.application` and turning `nyx_cli/cli.py` into a pure argument parser and adapter completely resolves all circular dependency risks.

---

## 5. Backward Compatibility Requirements
The CLI contract must remain 100% backward compatible:
1. `nyx --version` and `nyx --help` must behave identically.
2. The executable alias `nyx` must continue pointing to `nyx_cli.cli:main`.
3. All command flags (`--target`, `--force`, `--json`, `--severity`, `--type`, `--content`, `--file`, `--reason`, etc.) must maintain exact parameter signatures.
