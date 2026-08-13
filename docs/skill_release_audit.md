# NYX Skill Release Audit & Classification Report

## 1. Executive Summary
This document classifies all 82 NYX Security Skills into Public Safe Skills (for open-source release) and Private Research Skills (preserved in `nyx_private_backup/`).

---

## 2. Skill Classification Matrix

### A. Public Safe Skills (`skills/public/`)
Generic reconnaissance, technology detection, common OWASP patterns, and standard security testing skills:
- `hunt-html-injection`: Standard HTML injection detection.
- `hunt-open-redirect`: URL parameter manipulation and open redirect checks.
- `hunt-clickjacking`: X-Frame-Options and CSP framing checks.
- `hunt-tls-network`: HSTS, SSL cipher suite, and DNS configuration checks.
- `hunt-exceptional-conditions`: Exception handling and error response analysis.
- `hunt-captcha-bypass`: CAPTCHA validation workflow logic checks.
- `web2-recon`: Subdomain enumeration and live host discovery pipeline.

### B. Private Research Skills (`nyx_private_backup/`)
Advanced exploitation chains, bug bounty methodology, vendor-specific attack patterns, enterprise VPN/IAM chains, and proprietary research playbooks:
- `bb-methodology`, `bugcrowd-reporting`, `evidence-hygiene`, `redteam-mindset`, `redteam-report-template`
- `cloud-iam-deep`, `enterprise-vpn-attack`, `m365-entra-attack`, `okta-attack`, `vmware-vcenter-attack`
- `apk-redteam-pipeline`, `ios-redteam-pipeline`, `meme-coin-audit`, `web3-audit`
- `hunt-sqli`, `hunt-rce`, `hunt-ssrf`, `hunt-xss`, `hunt-xxe`, `hunt-deserialization`

### C. Review Required (`skills/review_required/`)
Skills reserved for future classification.

---

## 3. Preserved Assets Summary
All 82 skills and 333 files have been verified and archived in `nyx_private_backup/backup_manifest.json` with SHA-256 integrity verification.
