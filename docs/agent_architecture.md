# NYX Autonomous Agent Layer Architecture

## 1. Executive Summary
Phase 16 implements the **NYX Autonomous Security Research Agent Layer** (`nyx/agent/`).
The agent layer functions as a controlled AI research assistant capable of target context analysis, research planning, explainable decision tracking, and execution proposals—strictly constrained by a **Mandatory Human Approval Gate**.

---

## 2. Architecture & Control Flow Diagram

```
                 Target Domain / Scope
                           |
                           v
               Agent Context Engine (`context.py`)
                           |
                           v
                Research Planner (`planner.py`)
                           |
                           v
              AI Reasoning Engine (`reasoning.py`)
                           |
                           v
             Decision Tracking Engine (`decisions.py`)
                           |
                           v
         =========================================
          MANDATORY HUMAN APPROVAL GATE (`approval.py`)
         =========================================
                           |
                     (YES Approved)
                           v
             Tool Execution Engine (`nyx.execution.*`)
                           |
                           v
                Evidence & Validation Layer
```

---

## 3. Core Safety Principles

1. **Mandatory Human Approval**: No active execution runs without explicit human approval via CLI (`nyx agent approve <id>`) or REST/Dashboard (`POST /api/v1/agent/approve/{id}`).
2. **Zero Business Logic Duplication**: Agent layer calls existing `nyx.application.*` and `nyx.core.*` services directly.
3. **Zero Reverse Imports**: `nyx/agent/*` maintains strictly 0 imports from `nyx_cli.cli`.
4. **State Machine Integrity**: Governed by `AgentStateMachine` (`IDLE -> ANALYZING -> PLANNING -> WAITING_APPROVAL -> EXECUTING -> VALIDATING -> REPORTING -> COMPLETED`).
