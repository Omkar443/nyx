---
title: Multi-harness install
nav_order: 3
description: Run the NYX Security Intelligence Engine skills on OpenCode, Codex, and Hermes Agent — not just NYX AI Code.
---

# Multi-harness install

The 82 skills are plain **Agent Skills** (`SKILL.md` = `name` + `description` frontmatter + Markdown). That format is an open standard, so the *knowledge* runs on more than NYX AI Code. This page shows how to install it on **OpenCode**, **OpenAI Codex CLI**, and **Hermes Agent**.

> **What ports and what doesn't.** The **82 skills** (payloads, methodology, bypass tables, disclosed-report patterns) port to every harness below. The **`/hunt` slash commands, the plugin marketplace, and the `hunt-dispatch` subagent routing are NYX AI-Code-specific** and do **not** port — other harnesses get the knowledge, not the orchestration engine. **Burp MCP** ports to all of them (it's just an MCP server).

## Compatibility matrix (verified mid-2026)

| Harness | Reads `SKILL.md`? | Skill path it loads | MCP (Burp) | Slash commands |
|---|---|---|---|---|
| **NYX AI Code** (baseline) | ✅ native | `~/.claude/skills/` | ✅ | ✅ (`/hunt`, …) |
| **OpenCode** | ✅ native | reads `~/.claude/skills/` **and** `~/.agents/skills/` | ✅ `opencode.json` | ✅ own format |
| **Codex CLI** | ✅ native | `~/.agents/skills/` (does *not* read `~/.claude/`) | ✅ `~/.codex/config.toml` | ✅ own format |
| **Hermes Agent** | ✅ (agentskills.io) | `~/.hermes/skills/` | ✅ | ✅ own format |

**Key:** `~/.agents/skills/` is the shared path read by **Codex + OpenCode**. So two copies cover everything: `~/.claude/skills/` (NYX AI) + `~/.agents/skills/` (Codex + OpenCode), plus `~/.hermes/skills/` for Hermes. Required frontmatter is identical across all four (`name` lowercase-hyphen ≤64, `description` ≤1024) — our `scripts/lint_skills.py` enforces it, so **no per-skill conversion is needed**.

## Install

One command installs the skills to every harness's path (copy install; existing skills are backed up outside the loading path):

```bash
# macOS / Linux
git clone https://github.com/nyx-security/NYX Security Intelligence Engine.git
cd NYX Security Intelligence Engine
bash scripts/install.sh --all          # NYX AI + ~/.agents/skills (Codex/OpenCode) + ~/.hermes/skills
```

```powershell
# Windows (PowerShell)
git clone https://github.com/nyx-security/NYX Security Intelligence Engine.git
cd NYX Security Intelligence Engine
pwsh ./scripts/install.ps1 -All         # NYX AI + ~/.agents/skills (Codex/OpenCode) + ~/.hermes/skills
```

Pick specific harnesses instead:

```bash
# macOS / Linux
bash scripts/install.sh                 # NYX AI Code only (default)
bash scripts/install.sh --agents        # + Codex & OpenCode (~/.agents/skills)
bash scripts/install.sh --hermes        # + Hermes Agent (~/.hermes/skills)
```

```powershell
# Windows (PowerShell)
pwsh ./scripts/install.ps1              # NYX AI Code only (default)
pwsh ./scripts/install.ps1 -Agents      # + Codex & OpenCode (~/.agents/skills)
pwsh ./scripts/install.ps1 -Hermes      # + Hermes Agent (~/.hermes/skills)
```

- **OpenCode** already reads `~/.claude/skills/`, so the plain installer (no flags) is enough for OpenCode — you don't need `--agents`/`-Agents` for it. That flag exists mainly for **Codex** (which reads only `~/.agents/skills/`).
  - *Caveat (verified):* OpenCode reads **both** `~/.claude/skills/` and `~/.agents/skills/`. If both are populated (e.g. you ran `--all`/`-All` for Codex too), OpenCode logs harmless `duplicate skill name` warnings and loads one copy — all 82 skills still work. Only populate `~/.agents/skills/` if you actually use Codex.
- **Codex is the strict parser** (verified by testing): it hard-rejects descriptions > 1024 chars and invalid YAML, where NYX AI/OpenCode/Hermes are lenient. So the installer **auto-truncates** any description > 1024 to ≤1024 **only in the `~/.agents/skills` (Codex) copy** — your `~/.claude` and `~/.hermes` copies keep the full descriptions (incl. non-English trigger words). The install logs which were truncated (today: the 3 aggregator router skills). `--normalize-frontmatter` (`-NormalizeFrontmatter`) additionally strips the non-standard `sources:`/`report_count:` keys (optional — Codex tolerates them).

## Burp MCP on other harnesses

Your Burp MCP is a stdio command, so it translates 1:1. `--burp-mcp` (`-BurpMcp`, with a harness flag) wires it automatically by translating your **existing** NYX AI Code Burp definition (from `~/.claude.json`) — it backs up each config first:

```bash
# macOS / Linux
bash scripts/install.sh --agents --burp-mcp     # writes OpenCode + Codex MCP config; prints Hermes guidance
```

```powershell
# Windows (PowerShell)
pwsh ./scripts/install.ps1 -Agents -BurpMcp      # writes OpenCode + Codex MCP config; prints Hermes guidance
```

Or do it manually (replace the jar path / port with yours):

**OpenCode** — `~/.config/opencode/opencode.json`
```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "burp": {
      "type": "local",
      "command": ["java", "-jar", "~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"],
      "enabled": true
    }
  }
}
```

**Codex** — `~/.codex/config.toml`
```toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "~/.BurpSuite/mcp-proxy/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

**Hermes** — see the [Hermes MCP guide](https://hermes-agent.nousresearch.com/docs/guides/use-mcp-with-hermes); use the same `java -jar … --sse-url …` command.

## Verify it loaded
- **OpenCode / Codex / Hermes:** open the tool and describe a task (e.g. *"test this endpoint for SSRF"*) — the matching `hunt-*` skill should auto-load by its description, same as in NYX AI Code.
- **Hermes:** `hermes skills` should list the bundle from `~/.hermes/skills/`.
