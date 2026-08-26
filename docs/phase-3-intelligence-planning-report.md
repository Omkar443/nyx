# NYX Phase 3 — Knowledge-Aware Intelligence & Deterministic Mission Planning Report

**Date:** 2026-08-25  
**Auditor / Implementer:** NYX Security Research Engine  
**Status:** PHASE 3 COMPLETE  

---

## 1. Architecture Overview (Before vs After)

Phase 3 establishes an integrated, knowledge-aware intelligence and deterministic mission planning architecture without compromising NYX's fail-closed security invariants.

```text
                                Engagement Context
                                       │
                                       ▼
                              ContextEngine
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
         Knowledge Retrieval                      AI Analysis Layer
     (search_knowledge / retrieve)             (Multi-Provider: Gemini,
                    │                           OpenAI, Claude, Grok, Groq)
                    │                                     │
                    │                              Advisory Reasoning
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                             Deterministic Planner
                    (MissionPlanner: Rules + Tested-Vector Memory)
                                       │
                                       ▼
                                Raw Plan Assembly
                                       │
                                       ▼
                              AIPolicyEngine Gate
                                       │
                                       ▼
                           Authorized Mission Plan
```

### Architectural Invariants Maintained
- **AI = Advisory Only:** AI output provides high-level security focus and context explanation. AI cannot authorize actions or expand scope.
- **Knowledge = Domain Intelligence:** The knowledge base provides structured vulnerability patterns and technology maps, but cannot directly execute commands.
- **Deterministic Rules = Decision Authority:** The rule engine (`_select_steps`) decides which security actions belong in the mission plan based on empirical target signals.
- **Policy Engine = Authorization Gate:** Every candidate plan step is evaluated against `authorization.yaml` and `target.yaml`. Unauthorized or out-of-scope actions are blocked.

---

## 2. Context-Aware Knowledge Retrieval (M3.1)

The knowledge retrieval layer (`nyx/core/knowledge.py`) has been upgraded to support multi-faceted queries and automatic context-driven extraction:

1. **Multi-Criteria `search_knowledge()`**:
   - Supports `technology: str | list[str]`, `keyword: str | list[str]`, `attack_surface: str`, `vulnerability_class: str`, `category: str`, and `phase: str`.
   - Distinguishes direct matches (name, category, stem) from indirect yaml text matches.
   - Calculates primary intent (`technology` vs `vulnerability`) deterministically.

2. **Automated `retrieve_context_knowledge(context)`**:
   - Automatically inspects discovered endpoints, detected technologies, findings, and phase from the target context.
   - Identifies attack surfaces (e.g., API, GraphQL, Authentication, File Upload, SSRF, Cloud Metadata).
   - Extracts top relevant vulnerability patterns, technology maps, recommended skills, and associated CVE references.

---

## 3. AI Analysis & Transparent Fail-Safe (M3.2 & Provider Parity)

All six AI providers (`gemini`, `openai`, `claude`, `grok`, `groq`, `local`) adhere to a strict structured analysis contract:

```json
{
  "recommended_focus": "<short focus title>",
  "analysis": "<reasoning tied directly to technologies/endpoints/findings>"
}
```

### Fail-Safe Degradation
If any AI provider experiences timeouts, network failure, unconfigured API keys, or returns malformed JSON:
- NYX does not hallucinate or fabricate responses.
- The manager automatically degrades to:
  ```json
  {
    "recommended_focus": "AI analysis unavailable — using deterministic methodology",
    "analysis": "AI provider execution error / unavailable"
  }
  ```
- The deterministic planner continues execution unimpeded.

---

## 4. Deterministic Planning Rules (M3.3)

In `nyx/ai/planner.py`, `MissionPlanner._select_steps(context)` enforces explicit, inspectable deterministic rules:

| Condition / Target Signal | Selected Mission Step | Reason Identifier | Knowledge Refs |
| :--- | :--- | :--- | :--- |
| **No endpoints (Discovery Phase)** | `httpx` (Fingerprinting) + `katana` (Harvesting) + `nyx-classify` (Mapping) + `nyx-triage` (Triage) | `INITIAL_HOST_DISCOVERY`, `ENDPOINT_HARVESTING_REQUIRED`, `SURFACE_MAPPING_AND_SKILL_ROUTING`, `HYPOTHESIS_VALIDATION_REQUIRED` | `["tech-fingerprint-001", "crawl-harvest-001", "skill-routing-engine", "7-question-gate"]` |
| **Financial GraphQL Mutation detected** | `nyx-classify` (GraphQL Financial Operations) | `FINANCIAL_GRAPHQL_MUTATION_DETECTED` | `["graphql-fintech-mutations", "graphql-node-id-idor", "hunt-fintech-graphql"]` |
| **Standard GraphQL detected** | `nyx-classify` (GraphQL Attack Surface) | `GRAPHQL_SURFACE_DETECTED` | `["graphql-node-id-idor", "hunt-graphql"]` |
| **Authentication Surface detected** | `nyx-classify` (Authentication State Analysis) | `AUTH_SURFACE_DETECTED` | `["auth-bypass-matrix", "hunt-auth-bypass", "hunt-ato"]` |
| **Known Framework detected** | `nyx-classify` (Framework Security Evaluation) | `KNOWN_TECHNOLOGY_DETECTED` | `["tech-matrix"]` + recommended skills |
| **General Endpoints fallback** | `nyx-classify` (Surface Mapping & Skill Matching) | `SURFACE_MAPPING_AND_SKILL_ROUTING` | `["skill-routing-engine", "tech-matrix"]` |
| **Findings with state = HYPOTHESIS** | `nyx-triage` (Controlled Finding Validation) | `HYPOTHESIS_VALIDATION_REQUIRED` | `["7-question-gate", "evidence-hygiene"]` |

---

## 5. Complete Decision Traceability (M3.4)

Every step in a generated mission plan contains deterministic traceability metadata:

```json
{
  "step": 1,
  "name": "Attack Surface Mapping & Skill Matching",
  "action": "technology_mapping",
  "tool": "nyx-classify",
  "reason": "FINANCIAL_GRAPHQL_MUTATION_DETECTED",
  "evidence": [
    "https://api.bank.com/payment/graphql?mutation=transferFunds"
  ],
  "knowledge_refs": [
    "graphql-fintech-mutations",
    "graphql-node-id-idor",
    "hunt-fintech-graphql"
  ],
  "policy_status": "PERMITTED"
}
```

---

## 6. Tested-Vector / Engagement Memory Integration (M3.5)

- **Vector Ledger Integration**: `ContextEngine` reads `.engagement/tested_vectors.json`.
- **Deduplication & Suppression**: `_is_vector_already_tested()` inspects whether a vector was previously attempted on the target endpoint.
- **Suppression Criteria**: Vectors with result `tested_negative`, `tested_success`, or `blocked_by_policy` are suppressed from generating redundant steps.
- **Retry Allowance**: Vectors with result `tested_inconclusive`, `failed_infrastructure`, or newly discovered endpoints are permitted for testing.

---

## 7. Security Boundary & Policy Verification

- [x] **AI Isolation:** AI cannot authorize execution, cannot add arbitrary tools, and cannot bypass scope checks.
- [x] **Fail-Closed Scope Gate:** Targets outside `.engagement/target.yaml` scope are immediately rejected with status `error`.
- [x] **Fail-Closed Policy Gate:** `AIPolicyEngine.filter_plan_steps()` verifies all tools and actions against authorization permissions, enforcing `dry_run: true` when `active_permitted: false`.
- [x] **Runtime Independence:** NYX operates with 0 external project dependencies.

---

## 8. Test Suite Verification

```text
============================= test session starts =============================
platform win32 -- Python 3.14.3, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\Pentest\Skill File\NYX
configfile: pyproject.toml
plugins: anyio-4.13.0
collected 151 items

tests\test_environment_bootstrap.py ................                     [ 10%]
tests\test_exec_sync.py ............                                     [ 18%]
tests\test_fixes_regression.py ............                              [ 26%]
tests\test_gemini_provider.py .....................                      [ 40%]
tests\test_grok_provider.py ........                                     [ 45%]
tests\test_groq_provider.py ........                                     [ 50%]
tests\test_mission_orchestration.py .                                    [ 51%]
tests\test_phase3_intelligence_planning.py ..........                    [ 58%]
tests\test_planner_execution.py ................                         [ 68%]
tests\test_provider_analysis.py ............                             [ 76%]
tests\test_release_block_1.py ......                                     [ 80%]
tests\test_scope_enforcement.py .....                                    [ 84%]
tests\test_surface_ranking.py ....                                       [ 86%]
tests\test_web_auth.py .......                                           [ 91%]
tests\test_websocket_frontend_auth.py ...                                [ 93%]
tests\test_worker_runtime.py ..........                                  [100%]

====================== 151 passed, 2 warnings in 36.35s =======================
```

- **Knowledge Integrity:** `KnowledgeProtection().verify_integrity()` confirmed 247 assets intact.
- **Skill Linter:** `scripts/lint_skills.py` verified 83 skills with 0 errors.

---

## 9. Before / After Metrics Table

| Dimension | Before Phase 3 | After Phase 3 | Status / Delta |
| :--- | :---: | :---: | :--- |
| **Total Test Suite** | 141 passed | **151 passed** | +10 new comprehensive intelligence tests |
| **Context-Aware Retrieval** | Keyword only | **Multi-criteria (Tech, Surface, Vuln, CVE)** | Implemented in `nyx.core.knowledge` |
| **AI Provider Fallbacks** | Generic text | **Strict fail-safe structured format** | Standardized across all 6 providers |
| **Planner Reasoning Engine** | Static rules | **Context-aware deterministic rules** | Reason identifiers for GraphQL, Fintech, Auth, Tech |
| **Tested-Vector Memory** | Unused in planning | **Integrated with `.engagement/tested_vectors.json`** | Deduplication & suppression active |
| **Decision Traceability** | Partial | **100% Traceable** | `reason`, `evidence`, `knowledge_refs`, `policy_status` |
| **Security Boundaries** | Intact | **Intact (Fail-closed)** | Verified |

---

## 10. Phase 3 Hard Stop Declaration

```text
PHASE 3 COMPLETE
```
All Phase 3 requirements (M3.1 through M3.6) have been implemented, tested, and verified. NYX is now knowledge-aware, memory-backed, and deterministically planned.
