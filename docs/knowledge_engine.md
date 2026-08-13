# NYX Knowledge Base & Skill Intelligence Engine

This document details the **NYX Knowledge Base**, **Intelligent Skill Router**, **Attack Surface Modeling**, and **Google Antigravity Integration** implemented in Phase 7.

---

## 1. Knowledge Base Architecture (`knowledge/`)

The Knowledge Base stores structured domain intelligence across technologies, vulnerability classes, and endpoint/parameter detection patterns.

```
knowledge/
├── vulnerabilities/
│   ├── authentication/   (e.g., auth_bypass.yaml)
│   ├── authorization/    (e.g., idor.yaml)
│   ├── injection/        (e.g., sqli.yaml)
│   ├── xss/              (e.g., reflected_xss.yaml)
│   ├── ssrf/             (e.g., aws_metadata.yaml)
│   ├── api/              (e.g., mass_assignment.yaml)
│   ├── cloud/            (e.g., s3_exposure.yaml)
│   └── mobile/           (e.g., hardcoded_secrets.yaml)
├── technologies/
│   ├── aspnet.yaml
│   ├── react.yaml
│   ├── graphql.yaml
│   ├── springboot.yaml
│   └── aws.yaml
└── patterns/
    ├── endpoint_patterns.yaml
    ├── parameter_patterns.yaml
    └── response_patterns.yaml
```

Each knowledge file specifies:
- `description`
- `attack_surface`
- `detection_patterns`
- `validation_steps`
- `evidence_requirements`
- `severity_mapping`
- `related_skills`

---

## 2. Intelligent Skill Router (`nyx.core.router`)

The Skill Router maps target contexts (URL endpoint paths, query parameters, detected technology stack components, and authentication states) against the NYX Knowledge Base to provide prioritized skill routing and research focus areas:

```python
from nyx.core.router import recommend_skills

rec = recommend_skills("http://testaspnet.vulnweb.com/login.aspx", technology="ASP.NET")
# Returns:
# {
#   "technology": "ASP.NET",
#   "attack_surface": ["authentication", "authorization", "session"],
#   "recommended_skills": ["hunt-aspnet", "hunt-auth-bypass", "hunt-ato"],
#   "priority": "HIGH"
# }
```

---

## 3. Attack Surface Modeling (`nyx.core.surface`)

The Surface Graph Builder models target infrastructure as a directed relational graph:

```
Target Node
   ├── Uses Technology ──> ASP.NET Node
   ├── Exposes Endpoint ──> /login.aspx Node
   │        └── Potential Vulnerability ──> Authentication Bypass Node
   └── Has Confirmed Finding ──> FH-2026-001 Node
```

Graph JSON Output:
```json
{
  "target": "testaspnet.vulnweb.com",
  "nodes": [
    { "type": "target", "value": "testaspnet.vulnweb.com" },
    { "type": "technology", "value": "ASP.NET" },
    { "type": "endpoint", "value": "/login.aspx" },
    { "type": "vulnerability", "value": "authentication vulnerability" }
  ],
  "edges": [ ... ]
}
```

---

## 4. Analysis Engine Integration (`nyx.core.analysis`)

`nyx.core.analysis.decision_context()` synthesizes target state, detected technology stacks, endpoint inventories, attack surface graphs, and knowledge base matches into a unified decision context summary:

```bash
nyx analyze context
```

Output:
```
==================================================
NYX Security Intelligence Context
==================================================

Target:
testaspnet.vulnweb.com

Detected Technology:
ASP.NET

Interesting Surfaces:

[HIGH]
Authentication
http://testaspnet.vulnweb.com/login.aspx

Potential Research Areas:

1. Authentication bypass
2. Session handling
3. Access control

Recommended Skills:
- hunt-aspnet
- hunt-auth-bypass
- hunt-ato
```

---

## 5. Google Antigravity Integration

Google Antigravity sidecar agents query `nyx.core.router` and `nyx.core.analysis.decision_context()` directly during research execution. When Antigravity identifies an ASP.NET target with `/login.aspx`, the Decision Context Engine routes the agent to load `hunt-aspnet`, `hunt-auth-bypass`, and `hunt-ato` skills automatically.
