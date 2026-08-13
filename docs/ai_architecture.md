# NYX AI Agent Architecture

## 1. Executive Overview
The **NYX AI Agent Integration Layer** transforms NYX from a security automation framework into a provider-agnostic, **AI-operated security intelligence platform**.

NYX core engine remains 100% independent. AI providers (Google Gemini, Anthropic NYX AI, OpenAI GPT, and Local LLMs) interface with NYX through standardized abstractions and strict security boundary enforcement gates.

---

## 2. Architecture Diagram

```
                 AI Providers & Agents

       Gemini      NYX AI       GPT      Local LLM

                      |
                      v

             nyx.ai.AIManager
         (Provider Abstraction)

                      |
                      v

            nyx.ai.ContextEngine
        (Target Context Aggregator)

                      |
                      v

            nyx.ai.MissionPlanner
         (Mission Reasoning Engine)

                      |
                      v

           nyx.security.AIPolicyEngine
        (Authorization & Scope Gate)

                      |
         +------------+------------+
         |                         |
         v                         v

 Application Services      MCP Preparation Layer
 (Recon / Exec / Finding)  (Tools / Resources / Schemas)
```

---

## 3. Core Architectural Guarantees

1. **Zero Provider Lock-in**: NYX core does not depend on any specific AI API SDK or vendor.
2. **Mandatory Security Policy Gate**: All AI decisions pass through `AIPolicyEngine`, verifying scope boundaries and requiring active authorization before execution.
3. **Decoupled Application Layer**: All AI actions execute through standard NYX Application Services (`AIService`, `ExecutionService`, `ReconService`, `FindingService`).
4. **Zero Reverse Imports**: `nyx/` modules maintain strictly 0 imports from `nyx_cli.cli`.
