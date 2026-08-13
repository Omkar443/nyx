# NYX Security Operations Dashboard Architecture

## 1. Executive Summary
Phase 15 adds a professional, local **Security Operations Dashboard & Web Platform** on top of the NYX Security Intelligence Engine.

The dashboard acts strictly as an **interface layer**. All security business logic, scope verification, authorization checks, state machine transitions, evidence sanitization, and execution policies remain centralized within NYX Application Services (`nyx.application.*`).

---

## 2. Platform Architecture Diagram

```
                 React + TypeScript SPA
                       (frontend/)
                            |
                            v
               FastAPI REST + WebSockets API
                        (nyx/web/)
                            |
                            v
                NYX Application Services
                   (nyx/application/*)
                            |
                            v
           NYX Core Intelligence & Validation
                   (nyx/core/*, nyx/security/*)
                            |
                            v
                 FileSystem & Tool Harness
                     (.engagement/, nyx/execution/)
```

---

## 3. Core Principles & Boundaries

1. **Zero Business-Logic Duplication**: The web layer (`nyx/web/`) and React frontend consume existing NYX services directly.
2. **Zero Reverse Imports**: `nyx/*` and `nyx/web/*` maintain strictly 0 imports from `nyx_cli.cli`.
3. **Local Authentication**: Uses `NYX_API_TOKEN` environment variable or generated workspace token file `.engagement/.web_token`.
4. **WebSocket Real-time Event Streaming**: `/ws/events` streams structured security events (`mission_started`, `recon_completed`, `finding_created`, `validation_completed`, `execution_finished`).
5. **Preserved CLI & Compatibility**: `nyx` and `nyx` CLI interfaces remain fully functional alongside `nyx web`.
