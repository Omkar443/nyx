# NYX Autonomous Research Methodology & Safety Protocols

## 1. Controlled Autonomy Model
The NYX Autonomous Agent is designed as a **force multiplier for human security researchers**, not an unguided scanner.

### Workflow Progression
1. **Mission Initialization**: `nyx agent start <target>` creates or attaches to target engagement context.
2. **Context Aggregation**: `AgentContextEngine` compiles target endpoints, detected technologies, scope rules, and historical findings.
3. **Research Planning**: `ResearchPlanner` formulates priority research objectives and selects matching NYX security skills.
4. **Action Proposal**: `DecisionEngine` records explainable action proposals with confidence scores and evidence requirements.
5. **Human Approval Gate**: Action enters `WAITING_APPROVAL`. Tool execution is blocked until human researcher approves.
6. **Execution & Validation**: Approved actions execute via `ExecutionService` and output is passed to `ValidationEngine`.

---

## 2. Decision Log Format & Explainability
Every proposed action generates an explainable decision record:
```json
{
  "action_id": "ACT-DF3948E9",
  "target": "example.com",
  "action": "Test IDOR vulnerability on user API",
  "tool_name": "subfinder",
  "reason": "Endpoint contains sequential ID parameter",
  "confidence": 85,
  "risk": "Medium",
  "evidence_required": ["request", "response", "differential_access"],
  "timestamp": "2026-08-13T17:51:25",
  "status": "PROPOSED"
}
```
