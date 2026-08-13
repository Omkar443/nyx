# NYX Multi-Agent Distributed Architecture Overview

## 1. Executive Summary
Phase 17 successfully transformed NYX into a **Multi-Agent Distributed Security Research Architecture**.

The system now orchestrates a fleet of specialized research agents (`ReconAgent`, `WebAgent`, `APIAgent`, `TechnologyAgent`, `ValidationAgent`, `ReportingAgent`) managed by a central **AgentController** with an event-driven **AgentMessageBus**, a priority-driven **DistributedTaskQueue**, and persistent event logging via NYX storage abstractions.

---

## 2. Multi-Agent Architecture Diagram

```
                             NYX Agent Controller
                            (nyx/agent/manager/)
                                     |
           +-------------------------+-------------------------+
           |                         |                         |
           v                         v                         v
     ReconAgent                  WebAgent                  APIAgent
 (asset & endpoints)       (web attack surface)       (API & IDOR vectors)
           |                         |                         |
           +-------------------------+-------------------------+
                                     |
                                     v
                        Agent Message Bus (bus.py)
                        & Task Queue (tasks.py)
                                     |
                                     v
                        Validation Engine (nyx.validation.*)
                                     |
                                     v
                        Evidence Vault (nyx.core.evidence)
```

---

## 3. Key Accomplishments

1. **Agent Manager Package (`nyx/agent/manager/`)**:
   - `controller.py`: `AgentController` managing specialized agent creation, task assignment, and fleet metrics.
   - `registry.py`: `AgentRegistry` supporting agent registration, lookup, and target/type/status filtering.
   - `scheduler.py`: `DistributedScheduler` matching queued tasks to capable registered agents.

2. **Specialized Agent Fleet (`nyx/agents/`)**:
   - `base.py`: `BaseSpecializedAgent` providing metadata, allowed skills/tools, and output schemas.
   - `recon_agent.py`: Asset discovery & endpoint harvesting.
   - `web_agent.py`: Web surface analysis & authentication testing.
   - `api_agent.py`: API endpoints, parameter tampering, and IDOR testing.
   - `technology_agent.py`: Tech stack fingerprinting.
   - `validation_agent.py`: 7-Question Gate and duplicate detection.
   - `reporting_agent.py`: Platform report writing (Bugcrowd, HackerOne, Intigriti).

3. **Message Bus & Task Queue**:
   - `bus.py`: `AgentMessageBus` publishing structured inter-agent events (`agent_started`, `task_assigned`, `analysis_completed`, `approval_required`, `execution_completed`, `validation_completed`) stored via NYX storage abstraction (`.engagement/database/agent_events.json`).
   - `tasks.py`: `DistributedTaskQueue` managing task creation, dependencies, priority ordering, and state transitions (`CREATED`, `QUEUED`, `RUNNING`, `WAITING_APPROVAL`, `COMPLETED`, `FAILED`).

4. **Application & Web API Services**:
   - `fleet_service.py`: `FleetService` application facade.
   - `routes/fleet.py`: REST routes (`/api/v1/fleet/agents`, `/api/v1/fleet/tasks`, `/api/v1/fleet/status`, `/api/v1/fleet/multi-start`).

5. **Dashboard & CLI Integrations**:
   - Created `frontend/src/views/FleetView.tsx` with Active Fleet Grid, Launch Agent Form, and Distributed Task Queue View.
   - Added `nyx agents list`, `create`, `stop`, `nyx tasks list`, `nyx fleet status` to `nyx_cli/cli.py`.
