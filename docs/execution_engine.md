# NYX Security Tool Orchestration Engine

## 1. Overview
The NYX Execution Engine (`nyx.execution.engine.ExecutionEngine`) provides a production-grade controlled execution environment for security tools. It handles authorization security gates, scope verification, pluggable tool adapters, dry-run generation, output sanitization, execution queueing, and artifact persistence.

---

## 2. Architecture & Layering

```
                 CLI / API / MCP / AI Agents

                           |
                           v

              nyx.application.execution_service

                           |
                           v

              nyx.execution.engine

                           |
        +------------------+------------------+
        |                  |                  |
        v                  v                  v

 Tool Registry       Execution Queue    Tool Adapters
 (.nyx/tools.yaml)   (nyx/execution/    (subfinder/httpx/
                      queue.py)          katana/nuclei/nmap)

                           |
                           v

              Infrastructure Layer
       (Storage / Logging / Security / Config)
```

---

## 3. Core Components

### 3.1 Domain Models (`nyx/models/execution.py`)
- `ExecutionStatus`: Enum (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`, `BLOCKED`)
- `ExecutionRequest`: Input data dataclass (`execution_id`, `tool_name`, `target`, `arguments`, `dry_run`, `active_permitted`)
- `ExecutionResult`: Output data dataclass (`execution_id`, `tool_name`, `status`, `exit_code`, `stdout`, `stderr`, `started_at`, `completed_at`, `artifacts`, `metadata`)

### 3.2 Execution Engine (`nyx/execution/engine.py`)
- Validates target authorization and scope boundaries via `nyx/security/authorization.py`.
- Dispatches command building and output parsing to specialized tool adapters (`nyx/execution/adapters/`).
- Enforces timeout limits and sandbox environment isolation (`prepare_isolated_env()`).
- Sanitizes all stdout and stderr output prior to logging and artifact storage.

### 3.3 Execution Queue (`nyx/execution/queue.py`)
- Supports prioritized enqueuing (`priority=1..10`), pending list inspection, and sequential batch execution (`execute_all(engine)`).

### 3.4 Artifact Manager (`nyx/execution/artifacts.py`)
- Persists stdout, stderr, result.json, and parsed metadata under `.engagement/executions/<EXECUTION_ID>/`.

---

## 4. Usage Examples

### Python API
```python
from nyx.application.execution_service import ExecutionService

svc = ExecutionService()

# Run tool
res = svc.run_tool("subfinder", "example.com", dry_run=True)
print(res.data)

# Query execution history
history = svc.get_history(limit=10)
print(history.data)
```

### CLI Commands
```powershell
# Run tool execution
nyx exec run subfinder example.com --dry-run

# Inspect execution status and artifacts
nyx exec status EXEC-1A2B3C4D

# View execution history
nyx exec history
```
