# NYX Benchmark: OWASP crAPI (Completely Ridiculous API)

This benchmark evaluates the **NYX Security Intelligence Engine** against OWASP crAPI — a microservices-based web application with an independent ground truth of vulnerabilities based on the OWASP API Security Top 10.

---

## Executive Summary

| Evaluation Tier | Result | Methodology & Details |
|---|:---:|---|
| **Ground Truth Baseline** | **21 Vulnerabilities** | 18 documented OWASP API Top 10 challenges + 3 secret challenges |
| **Recon & Organic Discovery** | **42 Endpoints** (100.0%) | 42 API routes discovered organically via JS-bundle parsing and content discovery |
| **Skill Routing & Knowledge Mapping** | **21 / 21** (100.0%) | 100% of attack surfaces mapped to specialized NYX security skills |
| **Automated Live Validated Findings** | **8 Confirmed** | Single-pass automated HTTP evidence capture + 7-Question Gate disk persistence |
| **False Positives** | **0** (0.0%) | 0 unverified or hallucinated findings |

---

## Pipeline Stage Breakdown

```text
TOTAL OFFICIAL VULNERABILITIES (21)
│
├── Stage 1: Recon & Discovery ──────────────► 21 / 21 passed (42 endpoints mapped organically)
│
├── Stage 2: Knowledge & Skill Routing ──────► 21 / 21 passed (100% matched to security skills)
│
└── Stage 3: Automated Live Probing & Triage ─► 8 Findings Confirmed & Persisted
                                               (13 complex multi-step/crypto/LLM chains require researcher follow-up)
```

### Stage 1: Recon & Discovery
- **SPA JavaScript Bundle Parsing**: Client-side route extraction crawls `<script src="...">` bundles to discover hidden REST/RPC API paths that are never linked in static HTML.
- **Wordlist Fuzzing**: Unlinked endpoints across microservice namespaces (`identity/`, `community/`, `workshop/`, `chatbot/`) mapped organically.

### Stage 2: Knowledge & Attack Routing (21 / 21)
- **21 vulnerabilities** successfully routed to specialized NYX skills (`hunt-idor`, `hunt-api-misconfig`, `hunt-jwt-crypto`, `hunt-business-logic`, `hunt-nosqli`, `hunt-file-upload`, `hunt-ssrf`, `hunt-brute-force`, `hunt-xss`).

### Stage 3: Automated Live Probing, Evidence Capture & 7-Question Gate Validation
In single-pass automated testing, NYX actively probes and confirms **8 real Finding records** backed by raw HTTP evidence in `.engagement/evidence/` and persisted to `.engagement/findings/` and the Web Dashboard:
- BOLA / IDOR in vehicle location lookup (`/api/v2/vehicle/<vin>/location`)
- Unauthenticated user PII leak via community post comments
- Sensitive mechanic order details exposure via IDOR
- Coupon code race condition / re-use bypass
- Mass assignment on user profile update
- Weak OTP rate limiting on password reset
- Unauthenticated file download via workshop endpoint
- JWT `alg:none` signature stripping acceptance

*The remaining 13 challenges involve asymmetric RS256 -> HS256 key confusion re-signing, client-side DOM markdown rendering injection, or multi-turn conversational prompt manipulation against autonomous LLM tool-calling loops, which are surfaced during analysis for manual researcher follow-up.*

---

## Reproducing the Benchmark

To reproduce the benchmark in your own environment:

```bash
# 1. Stand up crAPI locally via Docker
curl -o /tmp/crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip /tmp/crapi.zip && cd crAPI-main/deploy/docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d

# 2. Initialize engagement workspace
nyx engagement init http://127.0.0.1:8888

# 3. Run full NYX discovery and surface mapping
nyx recon http://127.0.0.1:8888
nyx surface http://127.0.0.1:8888

# 4. Generate AI mission plan and route security skills
nyx ai plan http://127.0.0.1:8888
nyx classify "http://127.0.0.1:8888/api/v2/vehicle/vehicles"

# 5. Launch the Web Dashboard to view live findings
nyx web --port 8000
```
