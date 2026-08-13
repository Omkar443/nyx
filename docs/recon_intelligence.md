# NYX Reconnaissance Intelligence Engine

This document describes the **NYX Recon Intelligence Engine** architecture, data models, endpoint scoring pipeline, parameter classification, and Google Antigravity integration implemented in Phase 8.

---

## 1. Recon Pipeline Architecture

```
                       Input Target / Scope
                                 |
                                 v
                       Subdomain & Host Discovery
                        (`nyx.recon.discovery`)
                                 |
                                 v
                       URL Normalizer & Deduper
                        (`nyx.recon.normalizer`)
                                 |
        +------------------------+------------------------+
        |                        |                        |
        v                        v                        v
JavaScript Analysis      API Discovery Engine      Technology Fingerprinting
(`nyx.recon.javascript`)   (`nyx.recon.api`)      (`nyx.recon.technology`)
        |                        |                        |
        +------------------------+------------------------+
                                 |
                                 v
                      Parameter Intelligence
                     (`nyx.recon.parameters`)
                                 |
                                 v
                     Attack Surface Scoring
                    (`nyx.recon.intelligence`)
                                 |
                                 v
                     NYX Decision Context Engine
                       (`nyx.core.analysis`)
```

---

## 2. Structured Data Models (`nyx/models/`)

- **`Asset`**: Asset metadata (domain, subdomains, live hosts, IP addresses, technologies).
- **`Endpoint`**: Endpoint properties (URL, HTTP method, discovery sources, detected technologies, parameters, risk score, priority).
- **`Technology`**: Stack fingerprint (name, category, version, confidence, headers).

---

## 3. Intelligent Endpoint Normalization (`nyx/recon/normalizer.py`)

Normalizes and canonicalizes target URLs:
- Lowercase domain names.
- Strips default HTTP (:80) and HTTPS (:443) ports.
- Collapses duplicate slashes and removes trailing slashes for deduplication (`/login/` ➔ `/login`).
- Sorts query parameters deterministically (`?b=2&a=1` ➔ `?a=1&b=2`).
- Removes URL fragment anchors (`#frag`).

---

## 4. Parameter Intelligence & Classification (`nyx/recon/parameters.py`)

Extracts and categorizes request parameters into security-relevant classes:
- **`object_identifier`**: `id`, `user_id`, `account_id`, `doc_id` ➔ Priority `HIGH` (Routes to `hunt-idor`).
- **`authentication`**: `token`, `session`, `jwt`, `api_key` ➔ Priority `HIGH` (Routes to `hunt-auth-bypass`, `hunt-ato`).
- **`injection_candidate`**: `query`, `search`, `filter`, `sort`, `cmd`, `url` ➔ Priority `HIGH` (Routes to `hunt-xss`, `hunt-sqli`, `hunt-ssrf`, `hunt-rce`).

---

## 5. Attack Surface Scoring (`nyx.recon.intelligence.score_endpoint`)

Calculates risk score (0-100) and priority (`HIGH`, `MEDIUM`, `LOW`):
- Base score: 20
- Authentication path match (`/login`, `/auth`, `/sso`): +30
- API path match (`/api/`, `/v1/`, `/graphql`): +25
- File upload/handling match (`/upload`, `/import`): +25
- Key technology stack present (ASP.NET, Spring, GraphQL): +20
- High-risk parameters present (`id`, `token`): +25

---

## 6. CLI Commands Reference

- **`nyx recon intelligence <target>`**: Generate structured Recon Intelligence summary.
- **`nyx recon js <url>`**: Extract JS files, API routes, and endpoints from JavaScript bundles.
- **`nyx recon api <url>`**: Fingerprint REST, GraphQL, and OpenAPI/Swagger API endpoints.
- **`nyx recon parameters`**: Demonstrate parameter classification and ranking logic.

---

## 7. Google Antigravity Integration

Google Antigravity agents execute `nyx recon intelligence <target>` at the start of engagement discovery. Discovered endpoints are automatically normalized, scored, and indexed in `.engagement/endpoints.json`. The Decision Context Engine then routes Antigravity sidecar agents directly to high-risk attack surfaces.
