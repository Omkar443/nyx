# NYX Security Intelligence Engine

<p align="center">
  <img src="assets/nyx_banner.png" alt="NYX Security Intelligence Engine Banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/Omkar443/nyx/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Version-1.0.0-success.svg" alt="Version 1.0.0"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/AI%20Provider-Neutral-purple.svg" alt="AI Provider Neutral"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Security%20Skills-82%20Loaded-brightgreen.svg" alt="82 Security Skills"></a>
  <a href="https://github.com/Omkar443/nyx"><img src="https://img.shields.io/badge/Quality%20Gate-7--Question-orange.svg" alt="7-Question Gate"></a>
</p>

---

## Overview

**NYX Security Intelligence Engine** (`nyx`) is an open-source, AI-model-neutral security research and tool orchestration framework. Designed for senior bug hunters, red-team operators, and application security engineers, NYX transforms raw LLM capabilities into an autonomous security researcher equipped with 82 specialized vulnerability playbooks, persistent engagement memory, SHA-256 evidence verification, and distributed execution nodes.

Whether backed by **Google Gemini**, **Anthropic Claude**, **OpenAI GPT-4**, or **Local LLMs (Ollama / vLLM)**, NYX maintains strict scope boundary enforcement, eliminates false positives through empirical validation gates, and streamlines the full lifecycle from discovery to report generation.

---

## Key Highlights & Pillars

- 🛡️ **82 Specialized Security Skills**: Per-vulnerability playbooks covering Web (SQLi, XSS, SSRF, IDOR, LFI, XXE, CORS), API (GraphQL, gRPC, WebSocket), Cloud (AWS, Azure, GCP, IMDS), Enterprise Identity (M365/Entra ID, Okta), Infrastructure (vCenter, SharePoint, Enterprise VPNs), and Mobile Red Teaming (Android APK, iOS IPA).
- 🧠 **AI Model Neutrality**: Unified abstraction layer supporting Gemini, Claude, OpenAI, and Local Ollama / vLLM endpoints with dynamic switching.
- 💾 **Persistent Engagement Memory**: Maintains structured JSON ledgers (`.engagement/`) tracking discovered subdomains, mapped technology stacks, tested attack vectors, and failed hypotheses.
- 🔒 **SHA-256 Cryptographic Evidence Vault**: Stores tamper-evident HTTP request/response logs, screenshots, and console traces with automated PII redaction.
- 🌐 **Distributed Worker Nodes**: Remote execution engine with HMAC-authenticated task dispatch for distributed recon, fuzzing, and surface probes.
- 🌐 **Dynamic Browser Runtime Engine**: Playwright-backed headless browser automation for JavaScript single-page application (SPA) mapping, DOM mutation tracking, and authenticated session state capture.
- 🎯 **7-Question Quality Gate**: Empirical validation workflow that enforces strict proof-of-impact, scope verification, and duplicate check before generating bug bounty reports.

---

## Architecture Flow Diagram

```mermaid
flowchart TD
    subgraph Client ["Interface & Dispatch Layer"]
        CLI["NYX CLI (nyx)"]
        WEB["React Web Dashboard"]
        REST["FastAPI REST & WebSocket Server"]
    end

    subgraph Governance ["Authorization & Scope Engine"]
        SCOPE["Scope Verification (.engagement/target.yaml)"]
        AUTH["Authorization Guard (.engagement/authorization.yaml)"]
        STATE["Workflow State Machine (DISCOVERY | ANALYSIS | VALIDATION | REPORTING)"]
    end

    subgraph Intelligence ["NYX Intelligence & Reasoning Core"]
        ROUTER["Skill Classifier & Router"]
        KNOWLEDGE["82 Security Skills Catalog"]
        MEMORY["Persistent Engagement Memory (.engagement/endpoints.json)"]
        DIFF["Asset Graph & Diff Engine"]
        AI_MGR["AI Provider Abstraction Manager"]
    end

    subgraph AI_Providers ["Supported AI Models"]
        GEMINI["Google Gemini"]
        CLAUDE["Anthropic Claude"]
        OPENAI["OpenAI GPT-4"]
        LOCAL["Local LLMs (Ollama / vLLM)"]
    end

    subgraph Execution ["Execution & Dynamic Runtime Engine"]
        SANDBOX["Subprocess Sandbox Executor"]
        BROWSER["Playwright Dynamic Browser Runtime"]
        WORKERS["Distributed Worker Fleet (HMAC Auth)"]
    end

    subgraph Lifecycle ["Finding Lifecycle & Quality Gate"]
        DUP_CHK["Duplicate Vector Check"]
        GATE["7-Question Quality Gate"]
        VAULT["SHA-256 Evidence Vault (.engagement/evidence/)"]
        REPORTS["Platform Report Generator (H1 / Bugcrowd / Intigriti / Immunefi)"]
    end

    Client --> Governance
    Governance --> Intelligence
    Intelligence --> AI_Providers
    AI_Providers --> Execution
    Execution --> Lifecycle
    Lifecycle --> REPORTS
```

---

## Installation & Quickstart

### Prerequisites
- **Python**: 3.10+
- **Node.js**: 18+ (for Web Dashboard)
- **Go / External Security Tools** (Optional): `subfinder`, `httpx`, `nmap`, `katana`

### 1. Installation via Pip

```bash
pip install nyx-security-engine
```

### 2. Installation from Source

```bash
git clone https://github.com/Omkar443/nyx.git
cd nyx
pip install -e .
```

### 3. Verify Environment Health

```bash
nyx doctor
```
*Expected Output:*
```text
======================================================================
NYX Security Intelligence Engine Environment Doctor
======================================================================
Python Version:  3.14.3
Platform:        win32
Repository Root: D:\Pentest\Skill File\NYX
Security Skills: 190 loaded
Active Workspace: READY (Uninitialized)

✓ NYX Environment & Intelligence Engine System Check: OK
```

---

## Usage Walkthrough

### Step 1: Initialize an Engagement Workspace

```bash
nyx engagement init target.com
```

### Step 2: Perform Passive Recon & Surface Ranking

```bash
# Run passive subdomain discovery & HTTP live probing
nyx recon target.com

# Rank the attack surface from recon manifest
nyx surface target.com
```

### Step 3: Classify Target Endpoint to Security Skills

```bash
nyx classify "https://api.target.com/v1/users/42?next=https://evil.com"
```

### Step 4: Run Quality Gate Triage on a Finding

```bash
nyx triage database/findings/FH-2026-001.md
```

### Step 5: Export Bug Bounty / Client Report

```bash
nyx report database/findings/FH-2026-001.md --platform bugcrowd --out draft.md
```

### Step 6: Launch Web Platform & Dashboard

```bash
# Build & start Web Dashboard on port 8000
cd frontend && npm run build && cd ..
nyx web --port 8000
```

---

## CLI Command Matrix

| Command | Subcommands / Arguments | Description |
|---|---|---|
| `nyx doctor` | None | Verify Python environment, skills registry, and workspace readiness |
| `nyx engagement` | `init <target>`, `status`, `export` | Manage persistent target workspace, scope boundaries, and ledger |
| `nyx recon` | `<target>` | Passive subdomain enumeration, DNS resolution, and live HTTP probing |
| `nyx surface` | `<target>` | Rank attack surface endpoints based on recon manifest data |
| `nyx classify` | `<url>` | Match URL parameters and path structures to the 82 security skills |
| `nyx memory` | `add`, `search`, `import-burp <file>` | Manage engagement memory ledger and import Burp XML HTTP history |
| `nyx evidence` | `list`, `show <id>`, `verify <id>`, `add` | Manage cryptographic SHA-256 evidence vault items |
| `nyx triage` | `<finding.md>` | Execute the 7-Question Quality Gate triage evaluation |
| `nyx report` | `<finding.md> --platform <h1\|bugcrowd...>` | Generate platform-formatted bug bounty submission drafts |
| `nyx web` | `--port 8000 --host 127.0.0.1` | Launch FastAPI web server & React Dashboard UI |
| `nyx monitor` | `start`, `stop`, `status` | Continuous attack surface monitoring and asset diffing engine |
| `nyx workers` | `list`, `register`, `status` | Manage remote HMAC-authenticated worker execution nodes |

---

## Supported AI Providers

NYX is completely model-neutral and can be configured with your preferred AI provider:

```bash
# Configure via Environment Variables or .env file
export NYX_AI_PROVIDER="gemini"         # choices: gemini, claude, openai, local
export GEMINI_API_KEY="AIzaSy..."
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export LOCAL_LLM_URL="http://localhost:11434/v1"
```

---

## Comprehensive Security Skill Catalog (82 Skills)

NYX includes an extensive library of specialized security skills automatically loaded based on context:

| Category | Count | Key Skills & Playbooks |
|---|---|---|
| **Web Application Vulnerabilities** | 13 | `hunt-xss`, `hunt-sqli`, `hunt-ssrf`, `hunt-idor`, `hunt-lfi`, `hunt-ssti`, `hunt-xxe`, `hunt-csrf`, `hunt-cors`, `hunt-open-redirect`, `hunt-html-injection`, `hunt-nosqli`, `hunt-dom` |
| **Authentication & Session** | 7 | `hunt-auth-bypass`, `hunt-session`, `hunt-oauth`, `hunt-saml`, `hunt-mfa-bypass`, `hunt-ato`, `hunt-forgot-password` |
| **API & Protocols** | 15 | `hunt-graphql`, `hunt-grpc`, `hunt-websocket`, `hunt-api-misconfig`, `hunt-host-header`, `hunt-rce`, `hunt-brute-force`, `hunt-captcha-bypass`, `hunt-shadow-api`, `hunt-spa-api`, `hunt-ldap` |
| **Concurrency & Complex** | 6 | `hunt-race-condition`, `hunt-http-smuggling`, `hunt-deserialization`, `hunt-cache-poison`, `hunt-exceptional-conditions`, `hunt-rag-vector` |
| **Framework Specific** | 4 | `hunt-nextjs`, `hunt-nodejs`, `hunt-laravel`, `hunt-springboot` |
| **Enterprise Identity & Cloud** | 3 | `m365-entra-attack`, `okta-attack`, `cloud-iam-deep` |
| **Enterprise Infrastructure** | 4 | `vmware-vcenter-attack`, `enterprise-vpn-attack`, `hunt-sharepoint`, `hunt-aspnet` |
| **Red Team Tradecraft** | 4 | `redteam-mindset`, `apk-redteam-pipeline`, `ios-redteam-pipeline`, `supply-chain-attack-recon` |
| **Recon & OSINT** | 4 | `web2-recon`, `offensive-osint`, `hunt-subdomain`, `recon-scope-triage` |
| **Workflow & Reporting** | 11 | `bb-methodology`, `triage-validation`, `evidence-hygiene`, `report-writing`, `bugcrowd-reporting`, `redteam-report-template`, `mid-engagement-ir-detection`, `security-arsenal`, `web3-audit`, `meme-coin-audit` |

---

## Security Policy, Scope & Authorized-Use Posture

NYX is calibrated specifically for authorized external-perimeter security research, bug bounty hunting, CTFs, and red-team engagements under explicit Rules of Engagement (RoE):

- 🔒 **Target Scope Verification**: Automatically validates `.engagement/target.yaml` and `.engagement/authorization.yaml` before executing active probes.
- 🎯 **7-Question Quality Gate (`nyx triage`)**: Enforces proof-of-impact, accepted program terms, and scope verification before report generation.
- 🛡️ **External Perimeter Focus**: Explicitly excludes internal Active Directory attacks (BloodHound, Kerberoasting, DCSync), C2 frameworks, LSASS dumping, and EDR evasion.
- 🔐 **Cryptographic Evidence Vault (`nyx evidence`)**: Auto-redacts session cookies, authorization headers, and user PII before writing evidence artifacts.

For full details on authorized use, explicit exclusions, supply-chain verification, and responsible disclosure, see the full [NYX Security Policy](SECURITY.md).

---

## Documentation Roadmap

- 📖 [Installation Guide](INSTALL.md)
- 📖 [Usage & Workflow Guide](USAGE.md)
- 📖 [Security Policy & Rules](SECURITY.md)
- 📖 [Contributing Guidelines](CONTRIBUTING.md)
- 📖 [Changelog](CHANGELOG.md)
- 📖 [Private Asset Protection Audit](docs/private_asset_audit.md)
- 📖 [Release Candidate Audit Report](docs/release_candidate_report.md)

---

## License & Credits

- **Code License**: [MIT License](LICENSE)
- **Content License**: [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE-CONTENT)
- **Project Lead & Author**: [Omkar443](https://github.com/Omkar443)

<p align="center">
  <b>NYX Security Intelligence Engine</b> — <i>"Empowering Security Researchers with Autonomous Intelligence & Empirical Rigor."</i>
</p>
