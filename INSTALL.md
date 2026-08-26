# Installation Guide

Step-by-step setup for the NYX Security Intelligence Engine skill bundle.

## Prerequisites

- **NYX AI Code** — install from https://claude.ai/download
- **macOS, Linux, or Windows** — macOS/Linux use the bash installers; Windows uses the native PowerShell installers
- **Python 3.9+** — for the `nyx` CLI runner

### Optional (recommended but not required)

- **Burp Suite** Professional or Community — https://portswigger.net/burp. `nyx --burp` routes traffic through Burp's proxy. Without Burp, the CLI runs in curl-only mode and everything still works.
- **Burp MCP Server** (BApp Store extension) — adds conversational hunting via NYX AI Code. Optional layer on top of Burp Pro. Skip if you don't have Burp.
- **`subfinder`** (ProjectDiscovery) — improves passive subdomain enum. Without it, `nyx recon` falls back to crt.sh alone.
- **Java** — required for Burp MCP if you install it.

### Choose your operating mode

| Mode | What you need | Best for |
|---|---|---|
| **Curl-only** | Just Python 3.9+ | Quick hunts, scripted automation, no GUI |
| **Burp proxy** (`nyx --burp`) | Add Burp Suite Pro/Community | All `nyx` traffic logged in Burp; one click to Repeater |
| **Burp MCP** (conversational) | Burp Pro + MCP extension + NYX AI Code MCP setup | Maximum LLM-driven workflow inside NYX AI Code |

All three modes are first-class supported. The skills + CLI work identically across them — you pick based on what you have installed and how you like to work.

## Step 1 — Clone this repo

```bash
# macOS / Linux
mkdir -p ~/security-research && cd ~/security-research

# Windows (PowerShell)
New-Item -ItemType Directory -Force -Path "$HOME\security-research"
cd "$HOME\security-research"

# both
git clone https://github.com/Omkar443/nyx.git
cd nyx
```

## Step 2 — Run the installer

```bash
# macOS / Linux
bash scripts/install.sh

# Windows (PowerShell)
pwsh ./scripts/install.ps1
```

> The repo ships a `.gitattributes` that forces LF line endings on shell and
> PowerShell scripts, so a **fresh clone installs cleanly** on every platform. If you
> have an **existing** checkout that already picked up CRLF (cloned before this
> `.gitattributes`), normalize it once with
> `git add --renormalize . && git checkout .` (or just re-clone) — a CRLF-corrupted
> script aborts with a `syntax error` and cannot fix itself.

This copies:
- All 82 skills → `~/.claude/skills/` (macOS/Linux) or `%USERPROFILE%\.claude\skills\` (Windows)
- All 15 slash commands → `~/.claude/commands/`
- The `hunt` scaffolder → `~/.claude/scripts/hunt.sh` (sourced from your `.zshrc`/`.bashrc`) on macOS/Linux, or `~\.claude\scripts\hunt.ps1` (dot-sourced from your PowerShell `$PROFILE`) on Windows

Existing skills with the same name are backed up to `~/.claude/install-backups/<timestamp>/` — **outside** the skills/commands directories, so backups never load as duplicate skills. Re-runs are non-destructive.

### Run on other harnesses (OpenCode · Codex · Hermes)

The skills are plain Agent Skills, so they also run outside NYX AI Code:

```bash
# macOS / Linux
./scripts/install.sh --all          # also installs to ~/.agents/skills (Codex + OpenCode) and ~/.hermes/skills (Hermes)
./scripts/install.sh --agents       # just Codex + OpenCode
./scripts/install.sh --hermes       # just Hermes
./scripts/install.sh --agents --burp-mcp   # also wire your Burp MCP into those harnesses
```

```powershell
# Windows (PowerShell)
pwsh ./scripts/install.ps1 -All          # Codex + OpenCode + Hermes
pwsh ./scripts/install.ps1 -Agents       # just Codex + OpenCode
pwsh ./scripts/install.ps1 -Hermes       # just Hermes
pwsh ./scripts/install.ps1 -Agents -BurpMcp   # also wire your Burp MCP into those harnesses
```

Slash commands, the plugin marketplace, and the `/hunt` engine are NYX AI-Code-only; other harnesses get the skill knowledge + Burp MCP. Full details and per-harness MCP snippets: [`docs/multi-harness.md`](docs/multi-harness.md).

## Step 3 — (Optional) Set up Burp MCP

**Skip this step if you don't have Burp Suite Pro.** The bundle works fine in curl-only mode (`nyx recon target.com` etc.). Set this up later when/if you adopt Burp.

In Burp Suite:
1. Go to **Extensions** → **BApp Store** → search for "MCP Server" → Install
2. Confirm the **Output** tab shows: `Started MCP server on 127.0.0.1:9876`
3. Note the path it extracted the proxy JAR to (typically `~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar`)

In your terminal:

```bash
# macOS / Linux
claude mcp add burp -s user -- java -jar ~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar
```

```powershell
# Windows (PowerShell)
claude mcp add burp -s user -- java -jar "$HOME\.BurpSuite\mcp-proxy\mcp-proxy-all.jar"
```

Verify in a fresh `claude` session:

```
/mcp
```

You should see `burp · ✓ connected`.

## Step 4 — Verify Environment & Skills

Run `nyx doctor` to verify that all skills, adapters, and CLI components are ready:

```bash
nyx doctor
nyx skills
```

All 83 security playbooks and 247 knowledge entries are bundled natively with zero external download dependencies required.

## Step 5 — Smoke-test

Open a fresh `claude` session in any folder:

```bash
claude
```

Try a hunt-class trigger test:

```
I have a reflected user input that's rendered into the page HTML — testing for XSS. What payloads should I try?
```

Expected: NYX AI triggers `hunt-xss` and walks you through detection patterns + payloads.

Try the validation flow:

```
/triage
```

Then describe a hypothetical finding. Expected: NYX AI runs the 7-Question Gate.

Try the engagement scaffold:

```bash
hunt acme-test
ls ~/Targets/acme-test/
```

Expected: a complete folder with `CLAUDE.md`, `scope.md`, `findings/`, `evidence/`, `submissions.txt`, `notes.md`, `.gitignore`.

If all three smoke tests pass, you're set up.

## Step 7 — Cleanup

Delete the test target:

```bash
# macOS / Linux
rm -rf ~/Targets/acme-test

# Windows (PowerShell)
Remove-Item -Recurse -Force "$HOME\Targets\acme-test"
```

Then go find a real program and put it to work. See [USAGE.md](USAGE.md) for the full workflow walkthrough.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `/mcp` doesn't show burp | Burp Suite not running, or extension not loaded | Re-open Burp, confirm Extensions tab shows MCP Server with "Loaded" checked |
| `hunt: command not found` (macOS/Linux) | Shell didn't pick up the `source` line | Restart your terminal, or `source ~/.zshrc` |
| `hunt` not recognized (Windows) | PowerShell didn't load the profile | Open a new PowerShell window, or `. $PROFILE`; check execution policy is `RemoteSigned` or less restrictive (`Get-ExecutionPolicy -List`) |
| Skills don't trigger as expected | Description-field keyword mismatch | Mention the bug class explicitly in your prompt (e.g., "I'm testing IDOR on this endpoint") |
| `burp - get_proxy_history_regex` returns empty | Burp's proxy history is empty for that target | Browse the target through Burp first to populate history |
| Python build errors during step 5 | Using system Python 3.9 | macOS: use Homebrew Python 3.12 (`/opt/homebrew/bin/python3.12 -m venv .venv`); Windows: use the official python.org installer or `py -3.12 -m venv .venv` |

## Uninstall

The installer writes a manifest of exactly what it placed (under
`~/.claude/.skill-manifests/NYX Security Intelligence Engine.txt`). Remove that footprint — and
**only** that footprint — with:

```bash
# macOS / Linux
bash scripts/install.sh --uninstall

# Windows (PowerShell)
pwsh ./scripts/install.ps1 -Uninstall
```

This removes the bundle's skills, slash commands, the `hunt.sh`/`hunt.ps1` script, and its
shell-rc source line. (Install backups under `~/.claude/install-backups/` are left in place; delete them manually if you want.)

If you installed via the **plugin** instead of the script: `/plugin uninstall NYX@omkar`.

Burp MCP, if you wired it, is removed separately: `claude mcp remove burp`.
