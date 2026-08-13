# Phase 13 — NYX Execution Engine Audit Report

## 1. Executive Summary & Existing Execution Flow
Prior to Phase 13, tool execution in NYX was handled primarily by `nyx/execution/executor.py` (`execute_tool()`).
The execution flow proceeded as follows:

```
CLI / Function Call -> execute_tool()
  ├── 1. Build command (build_command() in nyx/execution/command.py)
  ├── 2. Check policy & scope (check_policy() in nyx/execution/policy.py)
  ├── 3. Dry-run intercept (returns dummy ExecutionResult if dry_run=True)
  ├── 4. Execute sub-process with timeout (run_with_timeout() in nyx/execution/timeout.py)
  ├── 5. Sanitize output (sanitize_canonical_evidence() in nyx/security/authorization.py)
  └── 6. Log result to .engagement/database/executions.json
```

---

## 2. Component Inspection Summary

| File / Component | Responsibility | Current State / Limitations |
|---|---|---|
| `.nyx/tools.yaml` | Tool registry configuration | Contains basic fields (`binary`, `execution_class`, `allowed_args`, `timeout`, `required_authorization`). Lacks adapter binding, categories, required permissions, and output parsing metadata. |
| `nyx/execution/result.py` | `ExecutionResult` data model | Flat dataclass. Lacks `ExecutionStatus` enum, structured `artifacts` dict, `metadata` dict, and `to_json()` / `from_dict()` serialization. |
| `nyx/execution/executor.py` | Core `execute_tool()` runner | Monolithic function combining validation, policy check, process invocation, and logging. Lacks adapter dispatching, queue management, and artifact folder creation. |
| `nyx/execution/command.py` | Command builder | Validates allowed binary and arguments against `.nyx/tools.yaml`. |
| `nyx/execution/policy.py` | Execution class & scope policy | Enforces `PASSIVE`, `SAFE_ACTIVE`, `ACTIVE` execution boundaries and scope check against target. |
| `nyx/application/` | Application service facade layer | Lacks `ExecutionService`. CLI previously called `execute_tool()` directly or through `cmd_exec`. |
| `nyx/api/` | External API layer | Contains `tools.py`, `mission.py`. Lacks structured AI agent execution API (`nyx.api.execution`). |

---

## 3. Missing Capabilities Identified

1. **Pluggable Tool Adapters**: No adapter interface (`ToolAdapter`) for tool-specific parsing (e.g. extracting JSON subdomains from `subfinder`, live hosts from `httpx`, crawled endpoints from `katana`, vulnerabilities from `nuclei`).
2. **Execution Domain Models & Status Enum**: No `ExecutionRequest` dataclass or explicit `ExecutionStatus` enum (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`, `BLOCKED`).
3. **Dedicated Artifact Storage**: Executions log a flat JSON entry in `database/executions.json`, but do not maintain dedicated execution artifact folders (`.engagement/executions/<EXEC_ID>/stdout.txt`, `stderr.txt`, `result.json`).
4. **Execution Queue**: No queueing system (`ExecutionQueue`) for batching, prioritizing, or sequentially running tool workflows.
5. **Decoupled Application Service**: Missing `ExecutionService` in `nyx/application/` returning `ServiceResult`.
6. **AI Agent Interface**: Missing `nyx/api/execution.py` structured endpoint for autonomous agent invocation.

---

## 4. Target Architecture & Upgrade Path
Phase 13 resolves these missing capabilities while maintaining 100% backward compatibility with `execute_tool()` and 0 reverse coupling from `nyx/` to `nyx_cli.cli`.
