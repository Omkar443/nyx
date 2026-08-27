# NYX Benchmark: OWASP Juice Shop (v20.2.0)

This benchmark evaluates the **NYX Security Intelligence Engine** against OWASP Juice Shop (v20.2.0) — an independently maintained vulnerable web application with a ground-truth challenge set not authored or influenced by NYX.

---

## Executive Summary

| Evaluation Tier | Result | Methodology & Details |
|---|:---:|---|
| **Ground Truth Baseline** | **116 Challenges** | Official challenge database (`challenges.yml` / `/api/Challenges/`) |
| **Actionable Vulnerability Scope** | **109 Challenges** | 7 meta CTF / UI tutorial challenges excluded |
| **Recon & Endpoint Discovery** | **109 / 109** (100.0%) | 100% surface discovery across REST APIs, static assets, and unlinked endpoints |
| **Skill Routing & Knowledge Mapping** | **100 / 109** (91.7%) | Actionable surfaces accurately matched to specialized NYX security skills |
| **Out-of-Scope / Out-of-Model Scope** | **9 / 109** (8.3%) | 2 Web3/Smart Contract, 5 Static SCA/Dependency, 2 DOM/Non-HTTP |
| **Automated Live Validated Findings** | **12 Confirmed** | Fully verified via HTTP evidence, 7-Question Gate, persisted to disk & dashboard |
| **False Positives** | **0** (0.0%) | 0 unverified or hallucinated findings persisted |

---

## Pipeline Stage Breakdown

```text
TOTAL ACTIONABLE CHALLENGES (109)
│
├── Stage 1: Recon & Discovery ──────────────► 109 / 109 passed (100% surface mapping)
│
├── Stage 2: Knowledge & Skill Routing ──────► 100 / 109 passed (9 out-of-model misses)
│
└── Stage 3: Automated Live Probing & Triage ─► 12 Findings Confirmed & Persisted
                                               (88 complex/multi-round vectors require researcher follow-up)
```

### Stage 1: Recon & Endpoint Discovery (109 / 109)
- All 109 attack surfaces and endpoints discovered organically by `nyx recon` and `nyx surface`.
- Unlinked files, API routes, and static assets (`.env`, `openapi.json`, `.well-known/security.txt`, `/ftp/`, backups) mapped via content discovery.

### Stage 2: Knowledge & Attack Routing (100 / 109)
- **100 actionable challenge surfaces** accurately routed to specialized security skills (`hunt-sqli`, `hunt-idor`, `hunt-api-misconfig`, `hunt-jwt-crypto`, `hunt-business-logic`, `hunt-xss`, etc.).
- **9 Out-of-Model Misses**:
  - *Web3 / Smart Contract (2)*: Mint the Honey Pot (3★), Wallet Depletion (6★).
  - *Static SCA / Dependency (5)*: Frontend Typosquatting (5★), Legacy Typosquatting (4★), Supply Chain Attack (5★), Vulnerable Library (4★), Security Advisory (3★).
  - *DOM / Non-HTTP (2)*: Steganography (4★), Mass Dispel (1★).

### Stage 3: Automated Live Probing, Evidence Capture & 7-Question Gate Validation
In single-pass automated execution, NYX actively probes, captures raw HTTP request/response evidence, passes the 7-Question Quality Gate, and persists **12 confirmed Finding records** to `.engagement/findings/` and the Web Dashboard (`FindingsView`):

| Finding ID | Severity | Vulnerability Class | Endpoint | Verified Impact |
|---|---|---|---|---|
| `FH-2026-001` | **Critical** | SQL Injection (Auth Bypass) | `/rest/user/login` | Full administrative JWT token acquisition |
| `FH-2026-002` | **High** | SQL Injection (UNION SELECT) | `/rest/products/search` | Database tables & product catalog exfiltration |
| `FH-2026-003` | **Medium** | Sensitive Data Exposure | `/ftp/legal.md` | Unauthenticated legal & backup file disclosure |
| `FH-2026-004` | **Low** | Security Misconfiguration | `/metrics` | Unauthenticated Prometheus telemetry leak |
| `FH-2026-005` | **Low** | Information Disclosure | `/.well-known/security.txt` | Disclosure policy & contact exposure |
| `FH-2026-006` | **High** | IDOR / BOLA | `/rest/basket/2` | Cross-tenant shopping cart data read |
| `FH-2026-007` | **Low** | Information Disclosure | `/rest/admin/application-version` | Server version & framework disclosure |
| `FH-2026-008` | **High** | Mass Assignment | `/api/Users` | Privilege escalation via `role: admin` creation |
| `FH-2026-009` | **Medium** | IDOR / BOLA | `/rest/track-order/*` | Order tracking & customer PII disclosure |
| `FH-2026-010` | **Medium** | Information Disclosure | `/rest/user/security-question` | Security question scheme enumeration |
| `FH-2026-011` | **Medium** | Sensitive Data Exposure | `/rest/user/data-export` | GDPR user profile archive extraction |
| `FH-2026-012` | **Medium** | Reflected XSS | `/rest/products/search` | Script execution in search response |

*The remaining 88 challenge categories require multi-stage state transitions, manual token signing (e.g. RS256 -> HS256), or interactive prompt manipulation, which are flagged during analysis for researcher investigation.*

---

## Reproducing the Benchmark

To reproduce the benchmark in your own environment:

```bash
# 1. Stand up Juice Shop locally
docker run -d -p 3000:3000 bkimminich/juice-shop:v20.2.0

# 2. Initialize engagement workspace
nyx engagement init http://127.0.0.1:3000

# 3. Run full NYX discovery and surface mapping
nyx recon http://127.0.0.1:3000
nyx surface http://127.0.0.1:3000

# 4. Generate AI mission plan and route security skills
nyx ai plan http://127.0.0.1:3000
nyx classify "http://127.0.0.1:3000/api/graphql"

# 5. Launch the Web Dashboard to view live findings
nyx web --port 8000
```
