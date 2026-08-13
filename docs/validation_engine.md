# NYX Validation Intelligence Engine Architecture

This document describes the **NYX Validation Intelligence Engine**, skill registry system, finding lifecycle integration, and confidence calculation mechanics implemented in Phase 9.

---

## 1. Skill Migration & Registry System (`nyx.core.skills`)

NYX integrates all 82 existing security skills without duplicating vulnerability logic:

- **Loader**: Discovers `.agents/skills/` and `skills/` directories.
- **Metadata Parser**: Extracts skill name, description, category, target technologies, and validation requirements from `SKILL.md` frontmatter.
- **API Functions**:
  - `load_skills()`: Returns full dictionary of registered skills.
  - `search_skills(query)`: Keyword search over skill names, descriptions, and categories.
  - `get_skill(name)`: Retrieves specific skill specification.
  - `recommend_skills(url, technology)`: Recommends skills based on URL patterns and tech stack.

---

## 2. Validation Engine Architecture (`nyx/validation/`)

```
                 Finding Candidate / ID
                            |
                            v
               Validation Engine Dispatcher
                 (`nyx.validation.engine`)
                            |
         +------------------+------------------+
         |                                     |
         v                                     v
Validation Rule Lookup                Evidence Vault Matcher
 (`nyx.validation.rules`)            (`.engagement/evidence/`)
         |                                     |
         +------------------+------------------+
                            |
                            v
                 Confidence Calculation
               (`nyx.validation.confidence`)
                            |
                            v
               State Machine Transition
        (HYPOTHESIS ➔ VALIDATING ➔ CONFIRMED / REJECTED)
```

---

## 3. Vulnerability Validation Rules (`nyx/validation/rules.py`)

Validation specifications defined for core vulnerability classes:
- **Authentication Bypass**: Requires HTTP 200/204 response returning sensitive data without session tokens.
- **IDOR**: Requires User A context requesting User B resource ID with empirical HTTP 200 payload diff.
- **SQL Injection**: Requires SQL syntax injection probe and empirical database error traceback / boolean / time delay.
- **Reflected XSS**: Requires unescaped polyglot script reflection in HTML execution context.
- **Mass Assignment**: Requires protected property persistence in subsequent state reads.

---

## 4. Confidence Calculation Mechanics (`nyx/validation/confidence.py`)

Calculates finding confidence score (0-100%):
- Base confidence score (30-40%).
- Empirical evidence artifacts attached (+15-20%).
- Endpoint parameter match (+10%).
- Verified request/response diff (+20%).

Finding State Machine Transitions:
- Confidence >= 80% & no missing checks ➔ State transitions to `CONFIRMED`.
- Confidence < 40% & missing evidence ➔ State remains `VALIDATING` / `HYPOTHESIS`.
- Explicit rejection rule matched ➔ State transitions to `REJECTED`.

---

## 5. CLI Commands Reference

- **`nyx skills list`**: List all 82 registered security skills.
- **`nyx skills search <keyword>`**: Search skills by name or category (e.g. `nyx skills search idor`).
- **`nyx skills show <skill_name>`**: Display skill details, technologies, and validation requirements.
- **`nyx validate <finding-id>`**: Run Validation Engine audit on a finding.
- **`nyx validate rules <type>`**: Display validation rule checklist and rejection conditions.
