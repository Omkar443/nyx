# NYX Security Intelligence Engine

<p align="center">
  <img src="assets/nyx_banner.png" alt="NYX Security Intelligence Engine Banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/Omkar443/nyx/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Version-1.0.0-success.svg" alt="Version 1.0.0"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Tests-221%20Passed-brightgreen.svg" alt="221 Tests Passing"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Security%20Skills-83%20Validated-blueviolet.svg" alt="83 Security Skills"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Knowledge%20Assets-33%20Databases-blue.svg" alt="33 Knowledge Databases"></a>
  <a href="docs/benchmarks/"><img src="https://img.shields.io/badge/Benchmarks-68.8%25%20%7C%2081.0%25-informational.svg" alt="Empirical Benchmarks"></a>
</p>

---

## What is NYX?

**NYX** (`nyx`) is an open-source **Security Research & Bug Bounty Intelligence Platform** designed for application security engineers, bug bounty hunters, and red teams.

Unlike raw LLM prompts that suffer from hallucinations, lost context, and unverified claims, NYX combines **83 specialized offensive security skills**, **33 structured domain knowledge databases**, **multi-provider AI advisory reasoning**, **deterministic mission planning**, **real tool execution adapters**, and a strict **7-Question Empirical Validation Gate**.

NYX ensures that every reported finding is backed by **real HTTP request/response traffic, SHA-256 evidence hashing, and strict scope verification**—with **zero fake execution and zero hallucinated bugs**.

---

## Empirical Benchmark Baseline

NYX is evaluated against independently-maintained vulnerable applications with published, objective ground truths across two transparent tiers:

| Benchmark Target | Architecture | Skill Routing Accuracy | Automated Validated Findings | False Positives | Full Methodology |
|---|---|:---:|:---:|:---:|---|
| **OWASP Juice Shop v20.2.0** | Monolithic Node / Express / Angular | **91.7%** (100 / 109) | **12 Findings Confirmed** | **0%** (0 FP) | [docs/benchmarks/juice-shop.md](docs/benchmarks/juice-shop.md) |
| **OWASP crAPI** | Microservices / Reverse Proxy / Multi-DB | **100.0%** (21 / 21) | **8 Findings Confirmed** | **0%** (0 FP) | [docs/benchmarks/crapi.md](docs/benchmarks/crapi.md) |

*Full reproduction command sequences, live finding tables, and ground truth matrices are documented in [docs/benchmarks/](docs/benchmarks/).*

---

## Core Architecture & Invariants

NYX operates on a strict separation of concerns where AI advises, policy governs, deterministic planners schedule, and real evidence validates:

```
┌────────────────────────────────────────────────────────┐
│                   1. CONTEXT ENGINE                    │
│    (Target Domain, Scope Boundaries, Detected Stack)   │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│               2. KNOWLEDGE & SKILL BASE                │
│   (83 Security Skills + 33 Structured Domain YAMLs)    │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│                 3. AI ADVISORY LAYER                   │
│   (Gemini, Grok, Groq, Claude, OpenAI, Local Ollama)   │
│   * Advisory only: Cannot authorize or bypass policy   │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│            4. DETERMINISTIC MISSION PLANNER            │
│   (Context-aware action scheduling & decision graph)   │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│             5. AUTHORIZATION & SCOPE GATE              │
│    (Fail-closed pre-execution policy enforcement)      │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│               6. REAL EXECUTION ADAPTERS               │
│      (httpx, katana, subfinder, ffuf, nuclei, nmap)    │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│            7. EVIDENCE VAULT & VALIDATION              │
│   (SHA-256 Hashing, 7-Question Gate, 8-Class Status)   │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│         8. PERSISTENT ENGAGEMENT MEMORY                │
│   (Tested vectors, finding lifecycle & report drafts)  │
└────────────────────────────────────────────────────────┘
```

### The 10 Security Invariants
1. **AI is Advisory Only:** AI generates hypotheses and reasoning, but cannot directly invoke unapproved shell commands or override scope.
2. **Knowledge is Non-Executable:** Knowledge files provide structured attack patterns and citations without executable code.
3. **Planner is Deterministic:** Mission plans follow strict rule-based trees and historical memory ledgers.
4. **Policy Gate is Authoritative:** Active attacks require explicit authorization (`authorized: true`) and in-scope hosts.
5. **Real Subprocess Execution:** No mock/simulated scan results in production workflows.
6. **Empirical Evidence Required:** Findings require raw HTTP request/response traces or OOB callback logs to be marked `CONFIRMED`.
7. **Infrastructure Failure $
eq$ Negative Security:** Timeouts and connection drops are classified as `failed_infrastructure`, never as "not vulnerable".
8. **Surface Detection $
eq$ Finding Confirmation:** Finding an endpoint (e.g., `/graphql` or `/admin`) never manufactures a vulnerability finding without proof.
9. **Zero-Hallucination Gate:** The 7-Question Gate automatically filters out self-XSS, rate-limit noise, missing best-practice headers, and unproven claims.
10. **100% Repository Independence:** Zero third-party proprietary runtime locks.

---

## Key Features

- 🛡️ **83 Validated Security Skills:** Modular playbooks covering Web, API, Cloud IAM, M365/Entra, Okta, Mobile (APK/iOS), CI/CD, Container/K8s, and Business Logic.
- 🖥️ **Web Operations Dashboard:** Modern React/Vite web platform with live WebSocket streaming, attack surface explorer, multi-agent fleet control, tool execution console, and telemetry monitors.
- 📚 **33 Structured Knowledge Databases:** Verified vulnerability patterns and attack vectors mapped to real-world disclosed bug bounty research.
- 🎯 **Fail-Closed Scope Policy:** Enforces boundary checks (`CONFIGURED`, `UNCONFIGURED`, `OUT_OF_SCOPE`). Blocks active scans on unverified targets while allowing dry-run plan reviews.
- 🔌 **Native Tool Adapters:** Subprocess execution harnesses for `httpx`, `katana`, `subfinder`, `ffuf`, `nuclei`, and `nmap` with Native PATH / WSL dual-vector discovery and timeout isolation.
- 🧠 **Multi-Provider AI Abstraction:** Native support for **Google Gemini**, **xAI Grok**, and **Groq** with actionable quota/error classification; **Anthropic Claude**, **OpenAI**, and **Local LLMs (Ollama)** with deterministic offline fallback.
- 💾 **Persistent Engagement Memory:** Tracks discovered assets, technology stacks, and tested vectors in `.engagement/` to prevent duplicate scanning.
- ⚖️ **Deterministic 7-Question Gate:** Triage engine that scores findings based on real-world impact, unauthenticated reachability, and program terms.
- 📄 **Multi-Platform Report Generator:** Automatically drafts formatted vulnerability submissions for **HackerOne**, **Bugcrowd**, **Intigriti**, and enterprise red-team deliverables.

---

## Installation & Quickstart

### Prerequisites
- **Python**: 3.10+ (Tested through Python 3.14 on Linux, macOS, Windows, and WSL2)
- **Git**

### 1. Installation from Source

```bash
git clone https://github.com/Omkar443/nyx.git
cd nyx
python -m pip install -e .
```

### 2. Verify Environment Health

```bash
nyx doctor
```

*Example Output:*
```text
======================================================================
NYX Security Intelligence Engine Environment Doctor
======================================================================
System
  OS              ✓ WINDOWS / LINUX / MACOS
  Architecture    ✓ AMD64 / ARM64

Python
  Version         ✓ 3.10+
  pip             ✓ OK

Python Packages
  NYX Core        ✓ READY
  FastAPI         ✓ OK
  Uvicorn         ✓ OK

Security Knowledge
  Validated Skills:    83
  Knowledge Bases:     33

Result:
✓ NYX environment is fully operational and release-ready
```

---

## Standard Workflow

### Step 1: Initialize an Engagement Workspace

```bash
nyx engagement init target.com
```

### Step 2: Configure Authorization & Scope

Inspect `.engagement/target.yaml` and confirm authorized boundaries in `.engagement/authorization.yaml`:

```yaml
# .engagement/authorization.yaml
authorized: true
mode: "RESEARCH"
```

### Step 3: Run Passive Recon & Surface Ranking

```bash
# Discover subdomains, unlinked paths, and SPA JS API endpoints
nyx recon target.com

# Rank attack surfaces based on discovered routes
nyx surface target.com
```

### Step 4: Classify Endpoints Against Security Skills

```bash
nyx classify "https://api.target.com/v1/graphql"
```

### Step 5: Automated Intelligence Planning & Execution

```bash
# Generate a deterministic mission plan
nyx ai plan target.com

# Execute the plan under policy boundaries (dry-run or live)
nyx ai execute target.com --dry-run
```

### Step 6: Validate Evidence & Triage Findings

```bash
# Evaluate empirical evidence through the 7-Question Quality Gate
nyx triage .engagement/findings/FH-2026-001/finding.json
```

### Step 7: Export Submission-Ready Report

```bash
# Export platform-formatted report (choices: h1, bugcrowd, intigriti, redteam)
nyx report FH-2026-001 --platform bugcrowd --out draft_report.md
```

### Step 8: Launch the Web Dashboard

```bash
nyx web --port 8000
```

---

## 🖥️ Web Operations Dashboard

NYX includes a built-in, real-time web operations dashboard built with **React**, **TypeScript**, **Tailwind CSS**, and **FastAPI WebSocket Streaming**.

<p align="center">
  <img src="assets/dashboard.png" alt="NYX Web Operations Dashboard" width="100%" />
</p>

### Launching the Dashboard

Start the backend server and embedded web interface:

```bash
# Launch on default port (http://localhost:8000)
nyx web --port 8000

# Custom host and port (e.g. for remote or team environments)
nyx web --host 0.0.0.0 --port 8000
```

Once launched:
- 🌐 **Web Dashboard UI**: `http://localhost:8000`
- ⚡ **WebSocket Live Event Stream**: `ws://localhost:8000/ws/events`
- 📖 **Interactive API Documentation (Swagger)**: `http://localhost:8000/api/docs`

### Dashboard Views & Core Capabilities

The NYX Web UI provides a centralized interface for the entire research lifecycle:

| View | Purpose & Key Features |
|---|---|
| **🎯 Security Overview (Dashboard)** | Real-time target context, engagement phase, discovered endpoints, active vulnerability hypotheses, stack detection, and recent tool executions. |
| **🛡️ Findings & 7-Question Triage** | Live findings ledger, empirical evidence inspector, CVSS 3.1 & VRT category mapping, and single-click report generation for HackerOne, Bugcrowd, and Intigriti. |
| **🗺️ Deterministic Mission Planner** | Context-aware decision trees, automated step execution, and strategy formulation across discovery, analysis, and validation phases. |
| **📡 Attack Surface Explorer** | Discovered endpoint inventory, route priority ranking, query parameter mapping, and technology detection. |
| **💻 Execution History & Tool Harness** | Live process launcher with Native PATH & WSL dual-vector discovery (`httpx`, `subfinder`, `katana`, `nuclei`, `nmap`, `ffuf`, `curl`), live output streaming, and honest execution status badges (`COMPLETED`, `SKIPPED`, `UNAVAILABLE`, `BLOCKED`, `FAILED`). |
| **👥 Multi-Agent Fleet & Approvals** | Multi-agent autonomous worker control, action authorization approval queue, and task execution tracking. |
| **⚡ Engine Telemetry & System Health** | Live runtime telemetry, dynamic 83-skill inventory distribution, binary resolution matrix, worker status, and persistent vault integrity. |
| **🧠 Intelligence & AI Playbooks** | Multi-provider AI reasoning, vulnerability playbook generator, knowledge base search, and provider readiness checks. |
| **👁️ Evidence Vault** | Raw HTTP request/response logs with SHA-256 integrity verification, PII redaction, and reproducible PoC records. |
| **📈 Continuous Monitoring** | Scheduled cron monitoring jobs, new asset diff detection, and automated alerting. |
| **⚙️ Target & Scope Settings** | Engagement target configuration, in-scope whitelist domains/IPs, and exclusion rules. |

---

## Supported AI Providers

NYX is model-neutral. Configure your preferred AI provider via environment variables or `.env`:

```bash
# Provider Choices: gemini, grok, groq, claude, openai, local
export NYX_AI_PROVIDER="gemini"

# Provider Keys (only configure the one you use)
export GEMINI_API_KEY="AIzaSy..."
export GROK_API_KEY="xai-..."
export GROQ_API_KEY="gsk_..."
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export LOCAL_LLM_URL="http://localhost:11434/v1"
```

*Note: If no API key is provided, NYX automatically falls back to its deterministic rule engine with 100% functionality.*

---

## Security Skill Catalog (83 Validated Skills)

| Domain | Count | Key Skills & Playbooks |
|---|:---:|---|
| **Web Application Vulnerabilities** | 13 | `hunt-xss`, `hunt-sqli`, `hunt-ssrf`, `hunt-idor`, `hunt-lfi`, `hunt-ssti`, `hunt-xxe`, `hunt-csrf`, `hunt-cors`, `hunt-open-redirect`, `hunt-html-injection`, `hunt-nosqli`, `hunt-dom` |
| **Authentication & Identity** | 7 | `hunt-auth-bypass`, `hunt-session`, `hunt-oauth`, `hunt-saml`, `hunt-mfa-bypass`, `hunt-ato`, `hunt-forgot-password` |
| **API & Modern Protocols** | 11 | `hunt-graphql`, `hunt-grpc`, `hunt-websocket`, `hunt-api-misconfig`, `hunt-host-header`, `hunt-rce`, `hunt-brute-force`, `hunt-captcha-bypass`, `hunt-shadow-api`, `hunt-spa-api`, `hunt-ldap` |
| **Concurrency & Complex Vectors** | 6 | `hunt-race-condition`, `hunt-http-smuggling`, `hunt-deserialization`, `hunt-cache-poison`, `hunt-exceptional-conditions`, `hunt-rag-vector` |
| **Framework Specific** | 4 | `hunt-nextjs`, `hunt-nodejs`, `hunt-laravel`, `hunt-springboot` |
| **Enterprise Identity & Cloud** | 3 | `m365-entra-attack`, `okta-attack`, `cloud-iam-deep` |
| **Enterprise Infrastructure** | 4 | `vmware-vcenter-attack`, `enterprise-vpn-attack`, `hunt-sharepoint`, `hunt-aspnet` |
| **Red Team Tradecraft & Mobile** | 4 | `redteam-mindset`, `apk-redteam-pipeline`, `ios-redteam-pipeline`, `supply-chain-attack-recon` |
| **Recon & OSINT** | 4 | `web2-recon`, `offensive-osint`, `hunt-subdomain`, `recon-scope-triage` |
| **DeFi & Smart Contracts** | 2 | `web3-audit`, `meme-coin-audit` |
| **Methodology & Quality Assurance** | 11 | `bb-methodology`, `triage-validation`, `evidence-hygiene`, `report-writing`, `bugcrowd-reporting`, `redteam-report-template`, `mid-engagement-ir-detection`, `security-arsenal`, `hunt-dispatch`, `hunt-misc`, `hunt-fintech-graphql` |
| **Infrastructure & Cloud Config** | 3 | `hunt-cloud-misconfig`, `hunt-k8s`, `hunt-cicd` |
| **Network & Directory Surface** | 3 | `hunt-tls-network`, `hunt-ntlm-info`, `hunt-source-leak` |
| **Total Validated Skills** | **83** | **100% Passing Skill Linter (0 errors)** |

---

## Test Suite & Verification

NYX is backed by an automated regression test suite covering all security domains, policy enforcement gates, and failure taxonomies:

```bash
python -m pytest
```

```text
============================== test session starts ==============================
platform win32 / linux -- Python 3.10+
collected 221 items

tests/test_content_discovery.py .......                                  [  3%]
tests/test_engine_status.py ..                                           [  4%]
tests/test_environment_bootstrap.py ................                     [ 11%]
tests/test_exec_sync.py ............                                     [ 17%]
tests/test_fixes_regression.py .............                             [ 23%]
tests/test_gemini_provider.py .....................                      [ 32%]
tests/test_grok_provider.py ........                                     [ 36%]
tests/test_groq_provider.py ........                                     [ 39%]
tests/test_mission_orchestration.py ..                                   [ 40%]
tests/test_phase3_intelligence_planning.py ..........                    [ 45%]
tests/test_phase4_execution_validation.py ..........                     [ 50%]
tests/test_phase5_evaluation_hardening.py .............................. [ 63%]
....                                                                     [ 65%]
tests/test_planner_execution.py ................                         [ 72%]
tests/test_provider_analysis.py ............                             [ 78%]
tests/test_release_block_1.py ......                                     [ 80%]
tests/test_router_generalization.py ....                                 [ 82%]
tests/test_scope_enforcement.py ...........                              [ 87%]
tests/test_surface_ranking.py ....                                       [ 89%]
tests/test_web_auth.py .......                                           [ 92%]
tests/test_websocket_frontend_auth.py ...                                [ 94%]
tests/test_worker_runtime.py ..........                                  [100%]

====================== 221 passed, 2 warnings in 92.40s ========================
```

---

## Scope & Known Limitations

NYX is built for empirical, HTTP-observable web and API security testing — reconnaissance, vulnerability detection, and evidence-based validation over HTTP/HTTPS. It is not a general security scanner, and it does not claim coverage outside that model.

To keep this honest, NYX was benchmarked against two independently-maintained vulnerable applications with published ground truths:

1. **OWASP Juice Shop (v20.2.0)**: **100 / 109** actionable attack surfaces routed (**91.7%**), **12 findings automated and verified live on disk/dashboard**, **0%** false positives.
2. **OWASP crAPI**: **21 / 21** actionable attack surfaces routed (**100.0%**), **8 findings automated and verified live on disk/dashboard**, **0%** false positives.

### What NYX does not currently do

**Outside NYX's execution model entirely:**
NYX's evidence and validation model is built around HTTP request/response analysis. It does not currently perform:
- Static dependency / software composition analysis (SCA) — e.g. detecting vulnerable or typosquatted npm/pip packages by inspecting the dependency tree
- Blockchain / Web3 transaction analysis — smart contract interaction, wallet operations, or on-chain state inspection
- Client-side-only analysis — browser DOM automation, image/steganographic forensics, or any vulnerability class with no observable HTTP evidence

If your target's risk surface depends heavily on these categories, pair NYX with a dedicated SCA tool (e.g. `npm audit`, Snyk) or Web3-specific auditing tooling — NYX is not a substitute for those.

**Within scope, but beyond current reasoning depth:**
NYX's AI advisory and deterministic planner currently perform strongest on single-step and moderate-complexity findings backed by direct empirical evidence. They are less reliable on vulnerabilities requiring multi-stage exploitation chains — for example: blind SQL injection requiring extensive boolean/time-based extraction, asymmetric JWT RS256 -> HS256 key confusion re-signing, complex multi-turn LLM/agent prompt manipulation, race-condition exploitation, template-engine sandbox escapes, or credential/TOTP derivation chains spanning multiple requests and state transitions. NYX will typically flag related risk indicators (e.g. an endpoint accepting unsanitized input) but may not autonomously complete a multi-step exploit chain to full validation. Manual follow-up by a researcher is recommended for high-complexity findings NYX surfaces but does not fully validate.

### What NYX is reliable for

Based on the benchmarks, NYX consistently and correctly detects and validates: broken object level authorization (BOLA) / IDOR, business logic and pricing/coupon manipulation, OTP/MFA rate-limit bypasses, JWT misconfiguration (`alg:none`, basic secret leakage), file upload bypasses (size/type/path traversal), local file inclusion (LFI), SSRF, information disclosure via misconfigured endpoints, mass assignment, NoSQL injection, and unlinked/unreferenced asset discovery.

We publish these benchmark methodologies openly:
- [docs/benchmarks/juice-shop.md](docs/benchmarks/juice-shop.md) (Juice Shop benchmark trace)
- [docs/benchmarks/crapi.md](docs/benchmarks/crapi.md) (crAPI benchmark trace)

---

## Responsible Use & Security Policy

NYX is built strictly for **authorized security research, defensive posture evaluation, bug bounty programs, and authorized penetration testing**:

- **Authorization Gate:** Active scans require verified ownership or explicit written authorization.
- **Privacy & Hygiene:** Session cookies, Authorization headers, and sensitive customer PII are automatically redacted before evidence storage.
- **Out-of-Scope Exclusions:** NYX explicitly rejects internal Active Directory credential dumping, malware delivery, and EDR disruption tradecraft.

For vulnerability reporting and disclosure guidelines, see [SECURITY.md](SECURITY.md).

---

## License

- **Source Code**: [Apache License 2.0](LICENSE)
- **Security Knowledge & Content**: [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE-CONTENT)
- **Third-Party & Vendored Notices**: [LICENSE-THIRD-PARTY.md](LICENSE-THIRD-PARTY.md)
- **Author & Maintainer**: [Omkar](https://github.com/Omkar443)

<p align="center">
  <b>NYX Security Intelligence Engine</b> — <i>"Empowering Security Researchers with Autonomous Intelligence & Empirical Rigor."</i>
</p>
