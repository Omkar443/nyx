# NYX Security Intelligence Engine — Changelog

All notable changes and release milestones for NYX are documented in this file.

---

## [1.0.0] — Open Source Release

First public release of NYX. This release includes a full pre-release audit covering security hygiene, licensing, AI provider reliability, and empirical detection benchmarking against two independent, publicly-documented vulnerable applications.

### Fixed
- **Critical: fresh-install crash.** `pyproject.toml` was missing `pyyaml` and `python-dotenv` as declared dependencies despite the code requiring them at import time — every clean install would fail on first run (`nyx doctor`). Now installs and runs cleanly on a bare environment.
- **AI provider error classification.** Gemini quota exhaustion (429) and Grok zero-credit billing (403) were previously reported as generic "timeout" / "authentication failed" errors. Both now surface actionable, specific messages (retry windows, billing links, correct auth-failure vs. no-credits distinction).
- **Dead model references.** Removed defaults pointing to deprecated `gemini-2.0-flash` / `gemini-1.5-flash` (both return 404 from Google's API); updated to `gemini-2.5-flash`.
- **License inconsistency.** `NOTICE` incorrectly claimed MIT + CC BY 4.0 dual licensing; harmonized with the actual Apache-2.0 license in `LICENSE`/`pyproject.toml`.
- **Missing third-party attribution.** Vendored MIT-licensed skills (from `shuvonsec/claude-bug-bounty`) lacked the required accompanying license text. Added `LICENSE-THIRD-PARTY.md` with full attribution.
- **Scope-matching edge cases.** Hardened `is_hostname_in_scope()` with explicit port, scheme, and host isolation logic; added adversarial regression tests (port bypass, host bypass, scheme bypass, typosquat rejection, exclusion precedence).

### Added
- **Content discovery recon stage.** New wordlist-based unlinked-path discovery (`ffuf` adapter, with graceful stdlib fallback when `ffuf` isn't installed).
- **SPA JavaScript bundle parsing.** Recon now extracts client-side API routes referenced in JS bundles (React/Vue/Angular/Next.js), closing a major discovery gap for microservice/SPA-style targets.
- **Generalized knowledge routing.** 16 previously-unrouted vulnerability classes (mass assignment, business logic/pricing tampering, file upload abuse, LFI/path traversal, JWT attacks, security.txt discovery, infrastructure fingerprinting) now route to existing skills based on structural/parameter patterns rather than hardcoded URLs — verified against endpoints on domains never seen during development.
- **Documented, reproducible benchmarks.** `docs/benchmarks/juice-shop.md` and `docs/benchmarks/crapi.md` — full methodology, ground truth source, and exact CLI reproduction steps for two independently-maintained vulnerable applications.

### Known Limitations (see README for full detail)
- No coverage for static dependency/SCA scanning, Web3/blockchain interaction, or client-side-only (DOM/steganographic) vulnerability classes — outside NYX's HTTP-evidence execution model by design.
- Multi-step exploit chains (e.g. asymmetric JWT key confusion, blind SQLi extraction, race conditions, multi-turn LLM/agent state manipulation) are detected as risk indicators but not always autonomously chained to full validation — current ceiling of the AI advisory layer.

### Benchmark Results
| Target | Skill Routing Accuracy | Automated Live Validated Findings | False Positives |
|---|:---:|:---:|:---:|
| OWASP Juice Shop v20.2.0 | 91.7% (100/109) | 12 Findings Confirmed on Disk/Dashboard | 0% |
| OWASP crAPI | 100.0% (21/21) | 8 Findings Confirmed on Disk/Dashboard | 0% |

Full traces, methodology, and reproduction steps: `docs/benchmarks/`.

### Verification
- 221/221 automated tests passing, 0 regressions.
- Clean install verified from a bare virtual environment.
- Graceful degradation confirmed for missing external tools (`subfinder`, `ffuf`, `httpx` fall back automatically; `nuclei`/`nmap`/`katana` fail with clear, actionable errors).
- Full repository secrets/credential/identity audit — clean.
