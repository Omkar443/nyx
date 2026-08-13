# NYX Security Intelligence Engine & Google Antigravity Architecture

This document describes how the **NYX Security Intelligence Engine** integrates with **Google Antigravity** to form a persistent AI-agent security operating system.

---

## High-Level Architecture Overview

```
                        Google Antigravity
                                |
                                v
                            GEMINI.md
                                |
                                v
                    NYX Intelligence Engine
                                |
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
 Mission System           Tool Registry           Decision Engine
(`nyx.api.mission`)    (`.nyx/tools.yaml`)    (`nyx.core.analysis`)
        |                       |                       |
        +-----------------------+-----------------------+
                                |
                                v
                        NYX Core Engine
           (`nyx.core.recon`, `nyx.core.engagement`,
            `nyx.core.findings`, `nyx.core.evidence`)
                                |
                                v
               Security Skills & Evidence Vault
```

---

## Core Components

### 1. Antigravity Workspace Control (`GEMINI.md`)
`GEMINI.md` acts as the primary rule set loaded by Google Antigravity upon workspace initialization. It defines authorization boundaries, state transition rules, and memory recovery directives.

### 2. NYX Intelligence API (`nyx.api`)
Programmatic Python interface exposing structured operations to AI agent harnesses:
- `nyx.api.mission`: Mission orchestration (`init`, `status`, `run`).
- `nyx.api.tools`: Tool, workflow, and policy registry loader (`load_tools_registry`, `load_workflows`, `load_policies`).

### 3. Decision Context Engine (`nyx.core.analysis`)
Performs contextual reasoning over targets, technologies, and endpoint paths to output structured recommendations:
- Detects technology stack mappings.
- Recommends target security skills (`hunt-aspnet`, `hunt-graphql`, `hunt-oauth`, etc.).
- Ranks attack surface priorities (`P1`, `P2`, `KILL`).

### 4. Persistent Memory & Evidence Vault (`.engagement/` & `.nyx/`)
- `.engagement/`: Per-target workspace state (`target.yaml`, `authorization.yaml`, `state.json`, `endpoints.json`, `findings.json`).
- `.engagement/evidence/`: Sanitized, SHA-256 integrity-verified security evidence artifacts.
- `.nyx/`: Declarative engine capabilities (`tools.yaml`), state workflows (`workflows.yaml`), and safety policies (`policies.yaml`).

---

## Antigravity Interaction Model

1. **Session Start**: Antigravity reads `GEMINI.md` and checks `.engagement/` for prior context.
2. **Mission Execution**: Antigravity executes `nyx mission run <target>` to run structured recon, tech detection, and surface ranking.
3. **Skill Routing**: Antigravity queries `nyx.core.analysis.get_decision_context(url)` to load target-specific security skills.
4. **Validation & Evidence**: When vulnerabilities are validated, evidence is stored using `nyx.core.evidence.add()`, automatically sanitized, and linked to `nyx.core.findings`.
5. **Reporting**: Antigravity generates platform-formatted reports via `nyx.core.findings.report()`.
