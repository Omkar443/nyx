# Persistent Bug Hunting Lifecycle & Workflow Guide

This document describes the complete bug hunting lifecycle managed by the **NYX Security Intelligence Engine** framework on **Google Antigravity**.

---

## Workflow Overview

The framework operates as a **persistent AI bug hunting operating system**, enforcing strict authorization boundaries, persistent state progression, technology-to-attack mapping, and empirical finding validation.

```
       +-------------------------------------------------------+
       |             Authorization Safety Gate                 |
       |      (target.yaml & authorization.yaml check)          |
       +-------------------------------------------------------+
                                   |
                                   v
       +-------------------------------------------------------+
       |                  DISCOVERY PHASE                      |
       |  - Passive recon & subdomain enumeration              |
       |  - Endpoint discovery & asset inventory               |
       |  - Record in endpoints.json & technologies.json       |
       +-------------------------------------------------------+
                                   |
                                   v
       +-------------------------------------------------------+
       |                   ANALYSIS PHASE                      |
       |  - Code & parameter structure analysis                |
       |  - Technology attack mapping lookup                   |
       |  - Vulnerability hypothesis formulation              |
       +-------------------------------------------------------+
                                   |
                                   v
       +-------------------------------------------------------+
       |                  VALIDATION PHASE                     |
       |  - Controlled PoC execution                           |
       |  - Duplicate finding check (nyx duplicate-check)       |
       |  - 7-Question Validation Gate (nyx triage)            |
       +-------------------------------------------------------+
                                   |
                                   v
       +-------------------------------------------------------+
       |                  REPORTING PHASE                      |
       |  - VRT / CVSS 3.1 severity mapping                    |
       |  - Evidence hygiene & PII redaction                   |
       |  - Markdown report generation (nyx report)            |
       +-------------------------------------------------------+
```

---

## Phase Details

### Phase 1: DISCOVERY
- **Goal**: Map the attack surface without performing invasive actions.
- **Allowed Actions**: Passive DNS lookup, HTTP header fingerprinting, public endpoint collection.
- **CLI Helper Commands**:
  - `nyx engagement init <target>`
  - `nyx recon <target>`
  - `nyx memory add --type endpoint --value <url>`

### Phase 2: ANALYSIS
- **Goal**: Identify potential attack vectors based on tech stack and application behavior.
- **Allowed Actions**: Inspection of public JavaScript bundles, OpenAPI specs, URL structure analysis, technology attack map lookup.
- **CLI Helper Commands**:
  - `nyx state ANALYSIS`
  - `nyx technology map <technology>` (e.g. `graphql`, `react`, `aws`)

### Phase 3: VALIDATION
- **Goal**: Confirm vulnerability existence through minimal, non-destructive empirical proof.
- **Allowed Actions**: Parameter probing, authorization state testing, payload execution.
- **Validation Gates**:
  1. `nyx duplicate-check --endpoint <ep> --parameter <param> --vulnerability <vuln>`
  2. `nyx triage <finding_file.md>` (7-Question Gate)

### Phase 4: REPORTING
- **Goal**: Generate high-quality, actionable, VRT-aligned bug reports.
- **Allowed Actions**: Drafting submission markdown files, redacting sensitive tokens/PII.
- **CLI Helper Commands**:
  - `nyx state REPORTING`
  - `nyx report <finding_file.md> --platform bugcrowd`
  - `nyx engagement export`
