# NYX Phase 4 — Execution Map

**Date:** 2026-08-25  
**Auditor / Implementer:** NYX Security Research Engine  
**Status:** REAL EXECUTION VERIFIED  

---

## 1. Executive Summary

This execution map audits every plan step, action, tool adapter, and service in the NYX platform. Each action is verified for end-to-end operational validity, authorization gating, scope checking, subprocess handling, artifact storage, evidence collection, deterministic validation, and finding lifecycle transitions.

All production execution paths are **REAL** and free of simulations, fake verdicts, or fabricated findings.

---

## 2. Executable Plan Actions Audit Table

| Step Name | Action Identifier | Tool / Service | Input | Scope & Auth Check | Execution Mechanism | Output & Artifact | Evidence Generated | Validator | State Transition | Classification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **Technology Fingerprinting** | `passive_recon` | `httpx` / `ExecutionService` | Target URL / Hostname | `check_authorization()` + `is_hostname_in_scope()` | Subprocess CLI (`httpx -title -status-code -tech-detect -json`) with timeout & sandbox | Raw stdout/stderr JSON, `.engagement/artifacts/exec_<id>/` | HTTP status, headers, server banner, detected tech | `HttpxAdapter.parse_result()` | Updates `.engagement/technologies.json` | **REAL** |
| **Endpoint Harvesting** | `endpoint_harvesting` | `katana` / `ExecutionService` | Target URL / Hostname | `check_authorization()` + `is_hostname_in_scope()` | Subprocess CLI (`katana -u <target> -jc -jsonl`) with timeout & sandbox | JSONL crawled endpoints, `.engagement/artifacts/exec_<id>/` | Discovered URLs, paths, JS bundle links | `KatanaAdapter.parse_result()` | Updates `.engagement/endpoints.json` | **REAL** |
| **Subdomain Enumeration** | `subdomain_enum` | `subfinder` / `ExecutionService` | Target Domain | `check_authorization()` + `is_hostname_in_scope()` | Subprocess CLI (`subfinder -d <target> -json`) with timeout & sandbox | JSON discovered hostnames, `.engagement/artifacts/exec_<id>/` | Passive DNS, CT logs, certificates | `SubfinderAdapter.parse_result()` | Updates target scope / hosts inventory | **REAL** |
| **Vulnerability Scanning** | `vuln_scan` | `nuclei` / `ExecutionService` | Target URL / Hostname | `check_authorization()` + `is_hostname_in_scope()` | Subprocess CLI (`nuclei -u <target> -jsonl`) with timeout & sandbox | JSONL vulnerability findings, `.engagement/artifacts/exec_<id>/` | Matched template, raw request, response extract | `NucleiAdapter.parse_result()` | Creates `HYPOTHESIS` or `VALIDATING` findings | **REAL** |
| **Port Scanning** | `port_scan` | `nmap` / `ExecutionService` | Target Hostname / IP | `check_authorization()` + `is_hostname_in_scope()` | Subprocess CLI (`nmap -sV -T4 -oX`) with timeout & sandbox | XML / Nmap stdout, `.engagement/artifacts/exec_<id>/` | Open ports, service banners, TLS versions | `NmapAdapter.parse_result()` | Updates host service inventory | **REAL** |
| **Attack Surface Mapping** | `technology_mapping` | `nyx-classify` / `AnalysisService` | URL / Harvested Endpoints | `ContextEngine` scope validation | Deterministic URL parsing, regex heuristics, keyword & skill index | JSON classification metadata (category, matched skills, patterns) | URL path structure, parameters, technology hints | `AnalysisService.classify_url()` | Informs planner for next phase routing | **REAL** |
| **Finding Triage** | `finding_triage` | `nyx-triage` / `FindingService` | `finding.json` / markdown path | Workspace finding identity verification | 7-Question Gate evaluation against empirical evidence criteria | Triage JSON report with 7 answers, score, and verdict | HTTP request/response logs, OOB callbacks, PoC commands | `core_findings.triage_finding()` | `HYPOTHESIS` → `CONFIRMED` / `KILL` / `DOWNGRADE` | **REAL** |
| **Evidence Validation** | `evidence_validation` | `ValidationService` | Finding ID + Evidence IDs | Workspace finding identity verification | Deterministic rule matching (`VALIDATION_RULES`) & confidence calculation | Validation dict with score, passed/missing checks, state | `http_request`, `http_response`, `oob_interaction`, `concurrency_trace` | `ValidationService.validate_finding()` | `HYPOTHESIS` / `VALIDATING` → `CONFIRMED` / `CANDIDATE` | **REAL** |

---

## 3. Plan Step Execution Flow

```text
Target Domain / URL
        │
        ▼
   Policy Gate (AIPolicyEngine: check_action_permitted)
        │
        ├── [If active_permitted=False] ──► dry_run=True (Safe observation)
        └── [If active_permitted=True]  ──► Live subprocess execution
                                                     │
                                                     ▼
                                      Subprocess Adapter Execution
                                   (Timeout, Isolated Env, Sanitization)
                                                     │
                                                     ▼
                                      Artifact Store (SHA-256 Hashed)
                                                     │
                                                     ▼
                                      Evidence Extraction & Indexing
                                                     │
                                                     ▼
                                      Deterministic Validation Gate
                                    (VALIDATION_RULES / 7-Question Gate)
                                                     │
                                                     ▼
                                      Finding Lifecycle State Update
                                 (HYPOTHESIS ──► VALIDATING ──► CONFIRMED)
                                                     │
                                                     ▼
                                      Tested-Vector Memory Ledger
                                 (.engagement/tested_vectors.json)
```

---

## 4. Classification Summary

- **Total Execution Actions Audited:** 8
- **REAL:** 8 (100%)
- **PARTIAL:** 0
- **SIMULATED:** 0
- **UNIMPLEMENTED:** 0

All execution paths adhere strictly to empirical tool execution, fail-closed policy enforcement, deterministic evidence validation, and persistent engagement memory tracking.
