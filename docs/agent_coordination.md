# NYX Agent Coordination & Message Bus Protocols

## 1. Event Message Schema
Inter-agent communication is governed by the `AgentMessageBus`. Every event message adheres to a standardized JSON schema:

```json
{
  "sender": "ReconAgent",
  "receiver": "WebAgent",
  "event_type": "analysis_completed",
  "payload": {
    "target": "example.com",
    "discovered_endpoints": ["/api/v1/users", "/login"],
    "technologies": ["ASP.NET", "Microsoft-IIS"]
  },
  "timestamp": "2026-08-13T19:09:14"
}
```

---

## 2. Event Types & Lifecycle
- `agent_started`: Broadcast when a specialized agent instance is launched.
- `task_assigned`: Published when `DistributedScheduler` assigns a task to an agent.
- `analysis_completed`: Published when an agent completes reasoning context analysis.
- `approval_required`: Published when an agent proposes an active execution action.
- `execution_completed`: Broadcast after an approved tool execution finishes.
- `validation_completed`: Broadcast after `ValidationAgent` evaluates a finding.
