# NYX Benchmark: OWASP Juice Shop (v20.2.0)

This benchmark evaluates the **NYX Security Intelligence Engine** against OWASP Juice Shop (v20.2.0) — an independently maintained vulnerable web application with a ground-truth challenge set not authored or influenced by NYX.

---

## Executive Summary

- **Ground Truth Baseline**: 116 official challenges (challenges.yml)
- **Actionable Vulnerability Scope**: **109** (7 meta CTF / UI challenges excluded)
- **True Positives**: **75 / 109** (**68.8%**)
- **False Positives**: **0** (0% across all testing iterations)
- **False Negatives**: **34 / 109** (**31.2%**)

---

## Pipeline Stage Breakdown

`
TOTAL ACTIONABLE CHALLENGES (109)
│
├── Stage 1: Recon & Discovery ──────► 109 / 109 passed (0 misses)
│
├── Stage 2: Knowledge Routing ──────► 100 / 109 passed (9 misses: out-of-scope Web3/SCA/DOM)
│
└── Stage 3: Execution & Validation ─► 75 / 100 passed (25 misses: complex multi-round chains)
`

### Stage 1: Recon & Endpoint Discovery
- All 109 endpoints and attack surfaces successfully discovered.
- Unlinked files, API routes, and static assets (.env, swagger.json, .sigma, backups) were mapped via native content discovery.

### Stage 2: Knowledge & Attack Routing
- **100 actionable vulnerabilities** routed to accurate security skills (hunt-idor, hunt-api-misconfig, hunt-jwt-crypto, hunt-business-logic, hunt-sqli, hunt-xss, etc.).
- **9 misses (Bucket B / Out-of-Model)**:
  - *Web3 / Smart Contract*: Mint the Honey Pot (3★), Wallet Depletion (6★).
  - *Static SCA / Dependency*: Frontend Typosquatting (5★), Legacy Typosquatting (4★), Supply Chain Attack (5★), Vulnerable Library (4★), Security Advisory (3★).
  - *DOM / Non-HTTP*: Steganography (4★), Mass Dispel (1★).

### Stage 3: AI Intelligence, Execution & Validation
- **75 vulnerabilities** fully verified and evidence-backed through the 7-Question Quality Gate.
- **25 misses**: High-difficulty (5★–6★) multi-step chains requiring iterative state management (e.g. blind boolean SQLi schema extraction, RS256 -> HS256 key confusion, HTTP/2 single-packet race conditions, template sandbox escapes).

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
```
