# NYX Security Skill Inventory Report

This document records the complete inventory of all **82 security skills** integrated into the NYX Intelligence Engine.

---

## 1. Inventory Summary

- **Total Skills Registered**: 82
- **Source Location**: `.agents/skills/` & `skills/`
- **Metadata Extraction**: Parsed directly from YAML frontmatter and `SKILL.md` content.
- **NYX AI Code Decoupling**: All slash commands (`/hunt`, `/chain`) replaced with Antigravity-native NYX CLI commands (`nyx mission run`, `nyx analyze context`, `nyx state`).

---

## 2. Skill Inventory Table

| Skill Name | Category | Target Technology | Vulnerability Class | NYX AI Dependencies | NYX Compatibility |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **apk-redteam-pipeline** | Mobile | Android / APK | Static & Runtime Secrets | None | Fully Compatible |
| **bb-methodology** | Orchestrator | Universal Web | Workflow Orchestration | Migrated | Fully Compatible |
| **bugcrowd-reporting** | Reporting | Bugcrowd | Submission Hygiene | None | Fully Compatible |
| **cloud-iam-deep** | Cloud | AWS / Azure / GCP | IAM Escalation / SSRF | None | Fully Compatible |
| **enterprise-vpn-attack** | Perimeter | Cisco / Fortinet / Citrix | Appliance Vulnerabilities | None | Fully Compatible |
| **evidence-hygiene** | Operations | Evidence Vault | Redaction & Hashing | None | Fully Compatible |
| **hunt-api-misconfig** | API | REST / GraphQL | Mass Assignment | Migrated | Fully Compatible |
| **hunt-aspnet** | Framework | ASP.NET | ViewState / MachineKey | None | Fully Compatible |
| **hunt-brute-force** | Auth | Login / OTP | Weak Rate Limiting | None | Fully Compatible |
| **hunt-business-logic** | Logic | E-Commerce / Billing | Cart / Coupon TOCTOU | None | Fully Compatible |
| **hunt-cache-poison** | CDN | CDN / Proxies | Cache Deception / Poison | None | Fully Compatible |
| **hunt-captcha-bypass** | Auth | CAPTCHA Logic | Validation Bypass | None | Fully Compatible |
| **hunt-cicd** | CI/CD | GitHub Actions / Jenkins | Workflow Injection | None | Fully Compatible |
| **hunt-clickjacking** | Web | Framing / CSP | UI Redressing | None | Fully Compatible |
| **hunt-cloud-misconfig** | Cloud | S3 / GCS / IMDS | Cloud Bucket / SSRF | None | Fully Compatible |
| **hunt-cors** | API | CORS Policy | Origin Reflection | None | Fully Compatible |
| **hunt-csrf** | Auth | Cross-Site Requests | SameSite Bypass / ATO | None | Fully Compatible |
| **hunt-deserialization** | Execution | Java / PHP / Python | Insecure Deserialization | None | Fully Compatible |
| **hunt-dom** | Client-Side | DOM XSS / postMessage | Client-Side Injection | None | Fully Compatible |
| **hunt-exceptional-conditions**| Logic | Stack Traces | Error Leaks | None | Fully Compatible |
| **hunt-file-upload** | Execution | Web Uploads | Webshell / Polyglot RCE | None | Fully Compatible |
| **hunt-forgot-password** | Auth | Password Reset | Token Exposure / Replay | None | Fully Compatible |
| **hunt-graphql** | API | GraphQL | Mutation IDOR / DoS | None | Fully Compatible |
| **hunt-grpc** | API | gRPC / HTTP/2 | Reflection / Transcoding | None | Fully Compatible |
| **hunt-host-header** | Web | Host Header | Password Poisoning | None | Fully Compatible |
| **hunt-html-injection** | Client-Side | HTML Render | Content Injection | None | Fully Compatible |
| **hunt-idor** | Access Control| REST / GraphQL | Direct Object Reference | Migrated | Fully Compatible |
| **hunt-jwt-crypto** | Crypto | JWT Bearer | Signature Stripping | None | Fully Compatible |
| **hunt-k8s** | Container | Kubernetes | Kubelet / Pod Escape | None | Fully Compatible |
| **hunt-laravel** | Framework | PHP Laravel | Debug RCE / .env | None | Fully Compatible |
| **hunt-ldap** | Injection | LDAP / AD | Auth Bypass / Exfil | None | Fully Compatible |
| **hunt-lfi** | File Access | LFI / RFI | Path Traversal / Poison | None | Fully Compatible |
| **hunt-mfa-bypass** | Auth | MFA / OTP | OTP Brute / Step Skip | None | Fully Compatible |
| **hunt-misc** | General | Diverse | Miscellaneous Bugs | None | Fully Compatible |
| **hunt-nextjs** | Framework | Next.js / RSC | Server Actions / ISR | None | Fully Compatible |
| **hunt-nodejs** | Framework | Node.js / Express | Prototype Pollution | None | Fully Compatible |
| **hunt-nosqli** | Injection | MongoDB / CouchDB | Operator Injection | None | Fully Compatible |
| **hunt-ntlm-info** | Auth | IIS / Exchange | NTLM Challenge Leak | None | Fully Compatible |
| **hunt-oauth** | Auth | OAuth / OIDC | redirect_uri Theft | None | Fully Compatible |
| **hunt-open-redirect** | Web | Redirect Logic | Open Redirect / ATO | None | Fully Compatible |
| **hunt-race-condition** | Logic | HTTP/2 Race | TOCTOU Double-Spend | None | Fully Compatible |
| **hunt-rag-vector** | AI / LLM | RAG Vector DB | Corpus Poisoning | None | Fully Compatible |
| **hunt-rce** | Execution | Command Execution | Remote Code Execution | None | Fully Compatible |
| **hunt-saml** | Auth | SAML SSO | XML Signature Wrap | None | Fully Compatible |
| **hunt-session** | Auth | Session Fixation | Invalidations / Hijack | None | Fully Compatible |
| **hunt-shadow-api** | API | Versioned APIs | API Inventory Regress | None | Fully Compatible |
| **hunt-sharepoint** | Web | SharePoint | SafeControl / SOAP | None | Fully Compatible |
| **hunt-source-leak** | Recon | Source Maps / .git | Credential Exposure | None | Fully Compatible |
| **hunt-spa-api** | API | Single Page Apps | Hidden Route Mapping | None | Fully Compatible |
| **hunt-springboot** | Framework | Spring Boot | Actuator Leaks / SpEL | None | Fully Compatible |
| **hunt-sqli** | Injection | SQL Database | SQL Injection | None | Fully Compatible |
| **hunt-ssrf** | Network | HTTP Handlers | Internal Resource Access| None | Fully Compatible |
| **hunt-ssti** | Execution | Template Engines | Template RCE | None | Fully Compatible |
| **hunt-subdomain** | Recon | DNS / CNAME | Subdomain Takeover | None | Fully Compatible |
| **hunt-tls-network** | Network | TLS / DNS | Network Misconfig | None | Fully Compatible |
| **hunt-websocket** | Web | WebSockets | CSWSH / Message Hijack | None | Fully Compatible |
| **hunt-xss** | Client-Side | DOM / Reflected | Cross-Site Scripting | None | Fully Compatible |
| **hunt-xxe** | Injection | XML Parsers | External Entity Access | None | Fully Compatible |
| **ios-redteam-pipeline** | Mobile | iOS / IPA | ATS / Cert Pinning | None | Fully Compatible |
| **m365-entra-attack** | Identity | M365 / Entra ID | Spray / CA Bypass | None | Fully Compatible |
| **meme-coin-audit** | Web3 | Solana SPL | Token Security Audit | None | Fully Compatible |
| **mid-engagement-ir-detection**| Monitoring| Client Infra | Defense Patch Diff | None | Fully Compatible |
| **offensive-osint** | Recon | OSINT | Asset Surface Mapping | None | Fully Compatible |
| **okta-attack** | Identity | Okta | Identity Spray / Push | None | Fully Compatible |
| **recon-scope-triage** | Recon | ASM Data | Scope Noise Filter | None | Fully Compatible |
| **redteam-mindset** | Methodology | Red Team | Operator Discipline | None | Fully Compatible |
| **redteam-report-template** | Reporting | Client Deliverable| Executive Reporting | None | Fully Compatible |
| **report-writing** | Reporting | Submissions | Platform Formatting | None | Fully Compatible |
| **security-arsenal** | Payloads | Payloads | Bypass & Payload Tables | None | Fully Compatible |
| **supply-chain-attack-recon** | Supply Chain | Build Packages | Dependency Confusion | None | Fully Compatible |
| **triage-validation** | Triage | Findings | 7-Question Gate | None | Fully Compatible |
| **vmware-vcenter-attack** | Perimeter | vCenter | Remote Execution | None | Fully Compatible |
| **web2-recon** | Recon | Web Infrastructure| Host Discovery | None | Fully Compatible |
| **web3-audit** | Web3 | Smart Contracts | DeFi Logic Audit | None | Fully Compatible |
