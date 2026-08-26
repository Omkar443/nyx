# Security Policy for NYX Security Intelligence Engine

## Scope and Authorized-Use Posture

**NYX Security Intelligence Engine** (`nyx`) is an AI-model-neutral security research and tool orchestration framework. It contains 82 specialized vulnerability playbooks, payloads, bypass tables, detection patterns, and platform report templates derived from publicly disclosed vulnerability reports and authorized red-team engagements.

The skills, tools, and execution modules in NYX are intended exclusively for use against assets you own or have explicit written authorization to assess:

- **Bug-Bounty Programs**: Assets explicitly listed in-scope on authorized platforms (HackerOne, Bugcrowd, Intigriti, Immunefi, YesWeHack, etc.).
- **Authorized Red-Team & Pentest Engagements**: Systems covered by signed Rules of Engagement (RoE) and authorization letters.
- **Capture-The-Flag (CTF)**: Authorized security training competitions and synthetic lab targets.
- **Owned Infrastructure**: Systems, applications, and networks owned and operated by you.

### Built-in Governance & Safety Gates

NYX includes automated validation gates that enforce safety before actions are executed:

1. **Scope Protocol Verification**: Checks `.engagement/authorization.yaml` and `.engagement/target.yaml` to ensure `authorized: true` and verifies target hosts against scope whitelists.
2. **7-Question Quality Gate (`nyx triage`)**: Q3 explicitly verifies that the asset is in scope; Q2 checks whether the demonstrated impact matches accepted program terms.
3. **Evidence Hygiene & Redaction (`nyx evidence`)**: Automatically masks Bearer tokens, active session cookies, private API keys, and victim PII before writing evidence to disk.
4. **Researcher-Side Hygiene**: Standardized Bugcrowd/H1 researcher posture (Bugcrowdninja email aliases, account state restoration) to signal legitimate testing to target anti-fraud teams.

---

## What NYX Explicitly Excludes

NYX does not contain and is strictly prohibited from being used for:

- **0-Day Weaponization**: Developing or weaponizing zero-day exploits against unauthorized targets.
- **Post-Exploitation & Lateral Movement**: Internal network pivots, C2 agent deployment, or domain privilege escalation.
- **Malware & Evasion**: Malware development, command-and-control (C2) frameworks, AMSI/EDR evasion techniques, or anti-forensic stealth tradecraft.
- **Unauthorized Scanning & Mass Fuzzing**: Unscoped internet-wide port scans, mass data exfiltration, or denial-of-service (DoS) attacks.
- **Supply-Chain Attacks**: Compromising third-party dependencies, typosquatting, or unauthorized upstream package manipulation.
- **Credential Stuffing & ATO**: Automated credential stuffing or account takeover against unauthorized targets.
- **Legal Compliance**: Any activity violating the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, India's Information Technology Act, the EU Cybercrime Directive, or equivalent local statutes.

If a vulnerability hypothesis requires going beyond authorized scope to demonstrate impact, NYX validation gates default to **DOWNGRADE** or **CHAIN REQUIRED** — never to "exploit further to prove it."

---

## Scope of Coverage — External Attack Surface Only

By design, NYX focuses on the **external attack surface boundary** — the perimeter between the public internet and authenticated production systems.

### Out-of-Scope by Design (Deliberate Boundary)

- **Internal Active Directory Attacks**: BloodHound, Kerberoasting, ASREProast, DCSync, DCShadow, Pass-the-Hash, Pass-the-Ticket, AD CS abuse, `ntlmrelayx`, `Responder`, `mitm6`, `PetitPotam`, `PrinterBug`.
- **C2 Framework Tradecraft**: Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel C4.
- **Post-Exploit / Persistence**: LSASS memory dumping, golden/silver ticket creation, registry persistence, scheduled task creation, WMI event subscriptions, COM hijacking, token theft, named-pipe impersonation.
- **Evasion Techniques**: AMSI bypasses, ETW patching, Sysmon evasion, AV/EDR direct/indirect syscalls.
- **L2 Internal Network Attacks**: LLMNR/NBT-NS poisoning, IPv6 SLAAC abuse, ARP spoofing.

**Reasoning**: Internal Active Directory and post-exploitation tradecraft carry fundamentally different operational risk profiles and detection footprints. NYX is calibrated specifically for external-perimeter security research.

If testing surfaces a valid internal credential during an external assessment, NYX's boundary ends at **"Credential discovered + access verified."** Handoff to specialized internal red-team tooling (Impacket, NetExec, CrackMapExec, Rubeus, Certify, BloodHound) is intentionally outside NYX's scope.

---

## Verifying What You Install (Supply-Chain Trust)

When running NYX, you load 82 security skills into your AI agent's context window. Agent skills are structured code and text assets — treat them with the same security posture as any software dependency.

### Defense-in-Depth Verification Steps

1. **Automated Skill Linter**: Run `python scripts/lint_skills.py` to validate `SKILL.md` frontmatter, structural formatting, and scan for leaked secrets or client identifiers.
2. **Zero Network Calls at Install**: Package installation (`pip install nyx-security-engine`) only copies local Python code and skill playbooks. No external network connections are opened during setup.
3. **Plaintext Auditability**: All 82 security playbooks in `skills/` and `.agents/skills/` are plain-text Markdown files. Inspect them prior to execution to verify prompts, regexes, and execution commands.
4. **Pin Releases**: Pin your deployment to specific tagged releases on GitHub (`https://github.com/Omkar443/nyx`) rather than tracking unreviewed commits.

---

## Reporting a Security Issue in NYX

If you discover a security vulnerability within the NYX repository itself (e.g., in Python CLI modules, execution sandboxes, web API endpoints, or installer scripts):

1. **Do NOT** open a public issue containing zero-day details.
2. Report the vulnerability directly via [GitHub Security Advisories](https://github.com/Omkar443/nyx/security/advisories) or contact maintainer **Omkar** via GitHub.
3. Include clear step-by-step reproduction steps, proof-of-concept details, and potential impact.

*Note: Please do not submit reports containing unauthorized exploitation evidence against third-party targets.*

---

## Vulnerability Disclosure & Responsible-Use Commitments

When NYX assists in discovering a vulnerability on an authorized target:

1. **Validate First**: Execute `nyx triage` (7-Question Quality Gate) to verify reproducibility and scope boundary compliance.
2. **Sanitize Evidence**: Run `nyx evidence` redaction protocols to mask session cookies, authorization headers, and third-party user PII.
3. **Submit Responsibly**: Report findings exclusively through official program channels (HackerOne, Bugcrowd, Intigriti, Immunefi, or authorized VDP mailboxes).
4. **Coordinate Disclosure**: Respect program confidentiality rules and wait for formal program public disclosure before publishing writeups.
5. **Rotate Test Credentials**: Invalidate and rotate any session tokens, API keys, or accounts used during validation tests.

---

## License & Liability

NYX Security Intelligence Engine is provided **"as is"** under the [Apache License 2.0](LICENSE), without warranty of any kind. The maintainers and contributors assume no liability for misuse, unauthorized testing, legal consequences, or operational damages resulting from the use of this software.

*If you are ever uncertain whether a target host or testing vector is authorized: **STOP and verify in writing before proceeding.***
