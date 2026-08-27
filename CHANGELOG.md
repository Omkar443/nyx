# Changelog

All notable changes to the **NYX Security Intelligence Engine** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-08-27

### Initial Public Release — General Availability

NYX v1.0.0 establishes an open-source, reproducible **Security Research & Bug Bounty Intelligence Platform** designed for application security engineers, bug bounty hunters, and red team operators.

### Key Highlights & Features

#### 1. Native Execution Pipeline & Finding Bridge
- **`nyx run-mission <target>`**: Unified end-to-end multi-agent execution pipeline orchestrating Discovery, Attack Surface Analysis, Tool Execution, Evidence Vaulting, and Finding Triage in a single native CLI workflow.
- **`ExecutionFindingBridge`**: Programmatic bridge that automatically consumes subprocess tool execution traces, extracts candidate findings, attaches raw HTTP request/response artifacts into `.engagement/evidence/` with SHA-256 cryptographic hashes, and passes findings through the 7-Question Gate.
- **Native Tool Adapters**: Process harnesses for `httpx`, `katana`, `subfinder`, `nuclei`, `ffuf`, and native security probes with timeout safety and environment sandboxing.

#### 2. Empirical Validation Engine & 7-Question Gate
- **Zero-Hallucination Policy**: Deterministic 7-Question Quality Gate requiring empirical proof of exploitability, unauthenticated reachability, and program terms alignment before confirming findings.
- **Evidence Vault**: Secure evidence storage with automatic PII/credential redaction and SHA-256 integrity verification.
- **Finding Lifecycle State Machine**: Formal state tracking (`HYPOTHESIS` -> `INVESTIGATING` -> `VALIDATED` -> `CONFIRMED` -> `REPORTED` / `REJECTED`).

#### 3. Security Skills & Knowledge Catalog
- **83 Validated Security Skills**: Modular security playbooks covering Web, API, Cloud IAM, M365/Entra, Okta, Mobile (APK/iOS), CI/CD, Container/K8s, and Business Logic.
- **33 Structured Knowledge Databases**: Curated vulnerability catalogs and technology attack maps derived from disclosed bug bounty writeups.
- **Intelligent Skill Routing**: Pattern matching and technology context mapping (`nyx classify`, `nyx skills recommend`, `nyx technology map`).

#### 4. Web Operations Dashboard
- **Modern React/Vite UI**: Single-page application built with React 19, TypeScript, and Tailwind CSS.
- **Real-Time WebSocket Streaming**: Live event feeds for tool execution logs, agent state changes, telemetry counters, and security alerts.
- **Full View Matrix**: Dedicated views for Overview, Findings & Triage, Mission Planner, Attack Surface Explorer, Tool Harness, Fleet & Approvals, Telemetry & Health, AI Playbooks, Evidence Vault, and Scope Settings.

#### 5. Multi-Provider AI Advisory Layer
- **Model-Neutral Architecture**: Pluggable provider system supporting Google Gemini (`gemini-2.5-flash`), xAI Grok (`grok-4.6`), Groq (`gpt-oss-120b`), Anthropic Claude, OpenAI, and Local LLMs (Ollama).
- **Advisory Separation of Concerns**: AI provides reasoning and hypotheses; deterministic planners and authoritative scope policy gates govern all execution actions.
- **Deterministic Offline Fallback**: Fully functional offline rule engine if no API keys are configured.

#### 6. Multi-Platform Report Drafting
- **Standardized Report Exporters**: Instant report generation formatted for **HackerOne**, **Bugcrowd** (including VRT classification and manual severity request override blocks), **Intigriti** (with CVSS 3.1 vectors), and **Immunefi** (with Foundry PoC templates).

#### 7. Quality Assurance & Test Verification
- **100% Passing Test Suite**: 226 automated unit and integration tests passing across all components.
- **Zero-Crash CLI Matrix**: Exhaustive QA audit verifying all 36 top-level commands, subcommands, and flags with zero unhandled exceptions.
