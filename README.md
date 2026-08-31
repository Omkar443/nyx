# NYX Security Intelligence Engine

<p align="center">
  <img src="assets/nyx_banner.png" alt="NYX Security Intelligence Engine Banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/Omkar443/nyx/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Version-1.0.0-success.svg" alt="Version 1.0.0"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Tests-226%20Passed-brightgreen.svg" alt="226 Tests Passing"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Security%20Skills-83%20Validated-blueviolet.svg" alt="83 Security Skills"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Knowledge%20Assets-33%20Databases-blue.svg" alt="33 Knowledge Databases"></a>
  <a href="docs/benchmarks/"><img src="https://img.shields.io/badge/Benchmarks-68.8%25%20%7C%2081.0%25-informational.svg" alt="Empirical Benchmarks"></a>
</p>

---

## What is NYX?

**NYX** (`nyx`) is an open-source **Security Research & Bug Bounty Intelligence Platform** designed for application security engineers, bug bounty hunters, and red teams.

NYX operates as an **advanced reconnaissance, skill-routing, intelligence planning, and human-in-the-loop triage engine** equipped with a native tool execution bridge. Rather than acting as an unconstrained or unsafe "zero-click exploit weapon," NYX combines **83 specialized offensive security skills**, **33 structured domain knowledge databases**, **multi-provider AI advisory reasoning**, **deterministic mission planning**, **real tool execution adapters**, and a strict **7-Question Empirical Validation Gate**.

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

### 1. One-Command Automated Setup (Recommended)

NYX includes an interactive, idempotent onboarding wizard that detects your OS, installs and validates dependencies, builds the frontend, and tests your AI provider before writing configuration:

```bash
# Clone the repository
git clone https://github.com/Omkar443/nyx.git
cd nyx

# Run the automated installer (Linux, macOS, WSL)
./install.sh
```

*Alternatively on any platform with Python 3.11+:*
```bash
python3 setup.py
# or anytime via CLI after install:
nyx setup
```

#### What the installer automatically handles:
- **Python Runtime & Packages**: Validates Python >= 3.11, installs all core and web dependencies via `pip install -e .[all]`.
- **Node.js & Web Dashboard**: Detects Node.js and npm, installs frontend dependencies, and compiles the production bundle (`frontend/dist/index.html`).
- **Security Tools**: Auto-installs `sqlmap` via pip if missing; auto-installs `nuclei` and `ffuf` via `go install` if the Go runtime is detected in PATH.
- **Interactive AI Provider Configuration**: Prompts for your AI provider, collects API keys via hidden/masked input, **tests live connectivity before saving**, and safely writes to `.env` (automatically creating a `.env.backup.<timestamp>` backup).
- **Ethical Authorization Protocol**: Sets up the initial `.engagement/` workspace structure after explicit consent confirmation.
- **Post-Install Validation**: Runs core unit test suite and provider health checks.
- **Idempotency**: Safe to re-run at any time—already-installed runtimes, compiled frontend bundles, and tools are detected and skipped cleanly.

#### Manual Prerequisites (if not already installed):
- **Go Runtime (Optional for Go tools)**: If building `nuclei` or `ffuf` from source, install Go (`sudo apt install golang` or from https://go.dev/dl/). Precompiled binaries placed in system PATH are also auto-detected.
- **SecLists Wordlists (Optional for ffuf)**: Detected at `/usr/share/seclists` (install via `sudo apt install seclists` on Debian/Kali/Ubuntu, or clone to `~/.local/share/seclists`).

---

### 2. Manual Installation (Fallback)

If you prefer manual setup without the interactive wizard:

```bash
# 1. Install Python dependencies
python3 -m pip install -e ".[all]"

# 2. Build the React Web Dashboard
cd frontend
npm install
npm run build
cd ..

# 3. Configure environment variables (.env)
cp .env.example .env  # Or create .env with your AI keys

# 4. Verify system environment
nyx doctor
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

### Step 5: Automated Intelligence Planning & Native Mission Execution

NYX supports both modular step planning and unified multi-phase mission execution with an automated `ExecutionFindingBridge`:

```bash
# Option A: Generate an advisory AI/deterministic plan
nyx ai plan target.com

# Option B: Execute an end-to-end multi-agent security assessment
# Automatically orchestrates Discovery, Analysis, Tool Execution, Evidence Vaulting, and 7-Question Validation:
nyx run-mission target.com
```

*When tools execute via the native pipeline, raw HTTP traffic traces are captured and bridged directly into `.engagement/evidence/` with SHA-256 integrity hashes, and automatically evaluated against the 7-Question Gate.*

### Step 6: Inspect Evidence & Triage Findings

```bash
# List verified findings on disk
nyx findings

# Inspect cryptographic evidence in the vault
nyx evidence list FH-2026-001
nyx evidence verify EV-2026-0001

# Manually evaluate empirical evidence through the 7-Question Quality Gate
nyx triage .engagement/findings/FH-2026-001/finding.json
```

### Step 7: Export Submission-Ready Report

```bash
# Export platform-formatted report (choices: h1, bugcrowd, intigriti, immunefi, redteam)
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

NYX is model-neutral and supports both cloud-hosted APIs and self-hosted local inference engines. The setup wizard (`./install.sh` or `nyx setup`) tests and validates credentials live before saving them to `.env`.

| Provider | Identifier | Default Model | Best For | Rate Limits |
|---|---|---|---|---|
| **Groq** *(Recommended)* | `groq` | `openai/gpt-oss-120b` | High-speed structured advisory reasoning | Free-tier TPM/daily token limits apply |
| **Google Gemini** | `gemini` | `gemini-2.5-flash` | Fast hosted analysis & broad context | Standard Google API quotas |
| **Local LLaMA / DeepSeek** | `local` / `llama` / `deepseek` | Custom local model | Zero cloud leakage, offline research, no rate limits | Dependent on local host GPU/CPU latency |
| **OpenAI** | `openai` | `gpt-4o` | High-accuracy triage review | Standard OpenAI API billing |
| **Anthropic Claude** | `claude` | `claude-3-5-sonnet` | Complex code & parameter analysis | Standard Anthropic API billing |
| **xAI Grok** | `grok` | `grok-2` | Specialized reasoning | Standard xAI API billing |

### Manual Configuration (`.env`)

```bash
# Set primary active provider (groq, gemini, local, openai, claude, grok)
NYX_AI_PROVIDER="groq"

# Provider Credentials (configure the provider(s) you use)
GROQ_API_KEY="gsk_..."
GEMINI_API_KEY="AIzaSy..."
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."
XAI_API_KEY="xai-..."

# Local LLaMA / DeepSeek Server URL (default: http://localhost:8000/chat)
LOCAL_LLAMA_URL="http://localhost:8000/chat"
```

*Note: If no AI provider is configured, NYX automatically falls back to its deterministic rule engine with 100% core scanning functionality.*

---

## What's Autonomous vs. What Needs Approval vs. What Doesn't Exist Yet

NYX enforces a strict operational taxonomy to guarantee safety, reproducibility, and human accountability:

```
                      ┌─────────────────────────────────┐
                      │    PASSIVE / NON-DESTRUCTIVE    │
                      │  (Autonomous — No Approval Req) │
                      └────────────────┬────────────────┘
                                       │
                      ┌────────────────▼────────────────┐
                      │   1. Passive Recon & Discovery  │
                      │   2. Tech Stack Fingerprinting  │
                      │   3. Router & URL Classification│
                      │   4. Hypothesis Generation      │
                      └────────────────┬────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼                                                     ▼
┌───────────────────────────────┐             ┌───────────────────────────────┐
│     ACTIVE / DESTRUCTIVE      │             │        NOT YET BUILT          │
│ (Requires Human Authorization)│             │          (v2 Scope)           │
├───────────────────────────────┤             ├───────────────────────────────┤
│ • sqlmap active injection     │             │ • AI-generated custom exploits│
│ • nuclei active template fuzz │             │ • Zero-day payload synthesis  │
│ • ffuf parameter/LFI fuzzing  │             │ • Automated multi-stage chains│
│                               │             │                               │
│ Approval Flow:                │             │ *NYX orchestrates vetted tools│
│   CLI: nyx agent approve <id> │             │  (nuclei/sqlmap/ffuf), not    │
│   Web: 1-click Approval Modal │             │  untested generated scripts.  │
└───────────────────────────────┘             └───────────────────────────────┘
```

### Fail-Closed Behavior on AI Outage
When operating in autonomous mode, if an AI provider fails (due to rate limits, HTTP 429 quota exhaustion, network timeouts, or unparseable responses), **the mission loop halts immediately with status `ai_unavailable`**. NYX will **never** silently fall back to guessing, will **never** manufacture unverified findings during an outage, and preserves all previously collected data in `.engagement/`.

---

## Tool Coverage & Validation Menu

NYX pairs deterministic parameter and routing classifications with specialized, industry-standard verification adapters:

| Vulnerability Class | Primary Tool | Secondary / Fallback | Selection & Verification Method |
|---|---|---|---|
| **SQL Injection (SQLi)** | `sqlmap` | `nuclei` (`-tags sqli`) | Parameter input detection -> least-invasive boolean/error probes first; data dumping requires explicit engagement authorization |
| **Local File Inclusion (LFI) / Traversal** | `ffuf` | `nuclei` (`-tags lfi`) | Stack-aware wordlist fuzzing with deterministic regex verification (`root:x:0:0`, PHP fatal errors) |
| **Command Injection (RCE)** | `nuclei` (`-tags rce,oast`) | Manual CLI | System parameter & utility detection (`cmd`, `exec`, `ping`, `dns-lookup`) |
| **Cross-Site Scripting (XSS)** | `nuclei` (`-tags xss`) | Manual inspection | Reflection surface & blog/content parameter analysis |
| **Authentication & Session Flaws** | `nuclei` (`-tags auth,jwt`) | Manual inspection | Login, registration, token exchange, and account recovery flows |
| **SSRF & Open Redirects** | `nuclei` (`-tags ssrf,redirect`) | OOB callback | URL redirect parameter routing (`url=`, `redirect=`, `dest=`) |
| **GraphQL Introspection & IDOR** | `nuclei` (`-tags graphql,idor`) | Custom queries | Query schema introspection & object identifier routing |

*Coverage Note: Template-based and signature-based validation can only verify vulnerabilities with known matching signatures. Legitimate potential vulnerabilities without pre-existing automated templates remain honestly categorized as `HYPOTHESIS` pending researcher verification.*

---

## Evidence Vault & Finding Lifecycle Model

NYX manages findings through a rigorous, unidirectional 6-state lifecycle backed by cryptographic evidence and two layers of false-positive defense:

```
  [HYPOTHESIS] ──► [TRIAGED] ──► [VALIDATING] ──► [CONFIRMED] ──► [REPORTED]
        │              │               │                 │
        └──────────────┴───────────────┴─────────────────┴──────► [REJECTED]
```

### Finding Lifecycle States:
- **`HYPOTHESIS`**: Surface pattern matched via classification or AI reasoning. Contains structured technical observations (why flagged, preconditions for exploitability, verification steps).
- **`TRIAGED`**: Passed initial scope and sanity filters.
- **`VALIDATING`**: Active verification probe proposed or in-flight with human authorization.
- **`CONFIRMED`**: Verified with empirical HTTP evidence passing both adapter-level content validation and AI evidence review.
- **`REJECTED`**: Confirmed as false positive, out of scope, or non-exploitable.
- **`REPORTED`**: Exported to submission-ready markdown (HackerOne, Bugcrowd, Intigriti, Red Team).

### Two-Layer False-Positive Defense:
1. **Deterministic Tool-Adapter Verification**: Tool adapters enforce content signatures (e.g. `ffuf` requires actual `/etc/passwd` structure or error signatures rather than status-code-only matches, with baseline response diffing).
2. **AI Evidence Review**: Raw HTTP response output is submitted to AI advisory review to evaluate empirical validity before any finding can be marked `CONFIRMED`.

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

NYX is backed by an automated regression test suite covering all security domains, policy enforcement gates, setup wizards, and AI providers:

```bash
python3 -m pytest
```

---

## Verified Benchmarks & Empirical Methodology

To ensure transparent and falsifiable evaluation, NYX is tested against benchmark targets using full CLI automation (zero manual file edits or synthetic modifications):

### 1. Mutillidae Front-Controller Benchmark (Tested August 2026)
- **Target**: `https://server.vulnapp.id/mutillidae/` (PHP Front-Controller Architecture)
- **Methodology**: Full autonomous mission loop (`nyx ai autonomous <target> --provider groq --max-iterations 30`) with query-router target extraction.
- **Results**: Discovered 56 live endpoints, mapped 130 router paths, and generated **27 structured hypotheses** across SQLi (`user-info.php`, `show-log.php`), Command Injection (`dns-lookup.php`), Stored/Reflected XSS (`add-to-your-blog.php`), LFI (`arbitrary-file-inclusion.php`), and Authentication.

### 2. Standard Benchmark Suites
- **OWASP Juice Shop v20.2.0**: **100 / 109** actionable attack surfaces routed (**91.7%**), **12 automated findings confirmed on disk/dashboard** ([docs/benchmarks/juice-shop.md](docs/benchmarks/juice-shop.md)).
- **OWASP crAPI**: **21 / 21** actionable attack surfaces routed (**100.0%**), **8 automated findings confirmed on disk/dashboard** ([docs/benchmarks/crapi.md](docs/benchmarks/crapi.md)).

---

## Known Limitations

- **Frontend Automated Test Coverage**: Frontend React components are currently verified through manual end-to-end testing; full automated browser test suite (Playwright/Cypress) is planned for a future release.
- **Custom Exploit Synthesis (v2 Scope)**: NYX does not construct bespoke exploit binaries or novel RCE payloads; it executes vetted security tooling (`nuclei`, `sqlmap`, `ffuf`).
- **AI Quota Latency Trade-offs**: Groq free tier provides fast inference but enforces strict TPM quotas; local providers (`local_llama`) provide unlimited offline execution with higher hardware-dependent inference latency.
- **Template Coverage Gaps**: Complex multi-stage business logic or exotic vulnerabilities lacking public Nuclei templates will remain in `HYPOTHESIS` status until manually confirmed by a researcher.

---

## Responsible Use & Security Policy

NYX is built strictly for **authorized security research, defensive posture evaluation, bug bounty programs, and authorized penetration testing**:

- **Authorization Gate:** Active scans require verified ownership or explicit written authorization (`authorized: true` in `.engagement/authorization.yaml`).
- **Privacy & Hygiene:** Session cookies, Authorization headers, and sensitive customer PII are automatically redacted before evidence storage.
- **Out-of-Scope Exclusions:** NYX explicitly rejects internal Active Directory credential dumping, malware delivery, and EDR disruption tradecraft.

For vulnerability reporting, see [SECURITY.md](SECURITY.md). For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

- **Source Code**: [Apache License 2.0](LICENSE)
- **Security Knowledge & Content**: [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE-CONTENT)
- **Author & Maintainer**: [Omkar](https://github.com/Omkar443)

<p align="center">
  <b>NYX Security Intelligence Engine</b> — <i>"Empowering Security Researchers with Autonomous Intelligence & Empirical Rigor."</i>
</p>
