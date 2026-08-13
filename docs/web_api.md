# NYX Web API Reference Specification

## 1. Authentication
All API endpoints (except `/health`) require Bearer or `X-API-Token` authentication:
```http
Authorization: Bearer <NYX_API_TOKEN>
X-API-Token: <NYX_API_TOKEN>
```

---

## 2. API Endpoint Reference

### Mission Endpoints
- `GET /api/v1/mission` — Retrieve current engagement mission status & active workflow state.
- `POST /api/v1/mission` — Initialize or reset engagement mission workspace.
- `POST /api/v1/mission/state` — Transition workflow state or switch workflow mode.
- `GET /api/v1/mission/history` — Export timeline state transition history.

### Attack Surface Endpoints
- `GET /api/v1/surface` — Get risk-ranked attack surface overview.
- `GET /api/v1/assets` — Get asset surface metrics (endpoint & technology counts).
- `GET /api/v1/endpoints` — Retrieve harvested endpoint inventory.
- `GET /api/v1/technologies` — Retrieve detected technology stack.
- `POST /api/v1/surface/recon` — Trigger passive reconnaissance workflow.

### Findings Endpoints
- `GET /api/v1/findings` — List all recorded finding hypotheses.
- `GET /api/v1/findings/{id}` — Get finding details and hypothesis record.
- `POST /api/v1/findings` — Create a new finding hypothesis.
- `POST /api/v1/findings/{id}/transition` — Transition finding lifecycle state (`HYPOTHESIS`, `VERIFIED`, `REJECTED`, `SUBMITTED`).
- `POST /api/v1/findings/{id}/triage` — Run 7-Question Gate and validation check.
- `POST /api/v1/findings/{id}/report` — Generate platform submission report draft (Bugcrowd, HackerOne, Intigriti).

### Evidence Vault Endpoints
- `GET /api/v1/findings/{id}/evidence` — List evidence artifacts attached to finding.
- `GET /api/v1/evidence/{id}` — Get evidence details and sanitized preview.
- `POST /api/v1/findings/{id}/evidence` — Attach note or file evidence artifact.
- `POST /api/v1/evidence/{id}/verify` — Verify SHA-256 integrity hash of evidence artifact.

### Tool Execution Endpoints
- `GET /api/v1/execution/history` — Get tool execution history log.
- `GET /api/v1/execution/{id}` — Get tool execution status and stdout/stderr artifacts.
- `POST /api/v1/execution/run` — Execute controlled security tool through execution engine.
- `POST /api/v1/execution/enqueue` — Enqueue execution request into priority queue.

### Intelligence & AI Endpoints
- `GET /api/v1/intelligence/context` — Retrieve aggregated security context for target.
- `GET /api/v1/skills` — List security skills catalog.
- `GET /api/v1/skills/recommend` — Recommend security skills for technology stack.
- `GET /api/v1/knowledge/search` — Search security research knowledge base.
- `GET /api/v1/ai/providers` — List registered AI providers (Gemini, NYX AI, OpenAI, Local).
- `POST /api/v1/ai/plan` — Generate policy-validated AI mission plan.

---

## 3. WebSocket Event Streaming (`/ws/events?token=<NYX_API_TOKEN>`)
Supported Events: `mission_started`, `mission_completed`, `recon_started`, `recon_completed`, `finding_created`, `finding_updated`, `validation_started`, `validation_completed`, `evidence_added`, `execution_started`, `execution_finished`.
