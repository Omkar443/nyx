# NYX Continuous Security Intelligence Platform Overview

## 1. Executive Summary
Phase 20 introduces the **Continuous Security Intelligence Platform** (`nyx/intelligence/`, `nyx/monitor/`, `nyx/alerts/`, `nyx/research/`, `nyx/knowledge/`).
NYX tracks target attack surfaces over time, stores historical asset snapshots, detects delta changes, raises real-time alerts, maps new surfaces to recommended skill playbooks, and safeguards security knowledge assets.

---

## 2. Platform Architecture Diagram

```
                       NYX Continuous Engine
                         (ContinuousService)
                                  |
      +---------------------------+---------------------------+
      |                           |                           |
      v                           v                           v
Asset Intelligence         Continuous Watcher          Alert Manager
(AssetGraph & History)     (SurfaceWatcher)            (AlertManager & Providers)
      |                           |                           |
      +---------------------------+---------------------------+
                                  |
                                  v
                    Research Opportunity Engine
                   (OpportunityEngine & Priority)
                                  |
                                  v
                    Knowledge Protection System
                    (KnowledgeProtection)
```

---

## 3. Core Modules
- `AssetGraph & AssetHistory`: Manages domain graph relationships and stores timestamped asset snapshots in `.engagement/database/asset_history.json`.
- `DiffEngine & ChangeDetector`: Computes delta diffs and identifies new endpoints, parameters, technologies, and auth changes.
- `MonitoringScheduler & SurfaceWatcher`: Schedules surface monitoring jobs and tracks execution states (`CREATED`, `RUNNING`, `COMPLETED`, `FAILED`).
- `AlertManager`: Dispatches security notifications to Dashboard, Webhook, and SIEM channels.
- `OpportunityEngine`: Maps surface changes to recommended NYX skill playbooks (e.g. GraphQL -> `hunt-graphql`).
- `KnowledgeProtection`: Creates archives of `skills/` and `.agents/skills/`, verifies YAML frontmatter syntax, checks SHA-256 hashes, and guards against accidental deletions.
