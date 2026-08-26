"""
NYX Local LLM / Rule-Based Engine Provider Integration
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from nyx.ai.base import AIProvider


class LocalLLMProvider(AIProvider):
    """Local LLM (Ollama, LM Studio, Offline Heuristic) Implementation."""

    provider_name: str = "local"

    def __init__(self, model_name: str = "llama3:8b", endpoint_url: Optional[str] = None):
        self.model_name = model_name
        self.endpoint_url = endpoint_url or "http://localhost:11434"

    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        if "mission" in prompt.lower() or "plan" in prompt.lower():
            return "Recommended Mission:\n1. Local surface inventory\n2. Endpoint & parameter harvest\n3. Rule-based vulnerability triage"
        return f"[Local LLM Provider ({self.model_name})] Generated response for prompt: {prompt[:50]}..."

    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None) -> Dict[str, Any]:
        target = context.get("target", "unknown")
        technologies = [str(t).lower() for t in context.get("technologies", [])]
        endpoints = context.get("endpoints", [])
        skills = context.get("skills", [])

        tech_str = " ".join(technologies)
        ep_count = len(endpoints)

        if any(k in tech_str for k in ["php", "apache", "nginx", "wordpress", "drupal", "joomla"]):
            focus = "PHP & Web Server Attack Surface Analysis"
            reasoning = (
                f"Target '{target}' exposes a PHP/Web Server stack with {ep_count} harvested endpoints. "
                "Prioritize inspecting file include patterns, parameter sanitization, and server configuration vectors."
            )
        elif any(k in tech_str for k in ["asp.net", "iis", "microsoft", "sharepoint", "wcf"]):
            focus = "ASP.NET & IIS Configuration Testing"
            reasoning = (
                f"Identified Microsoft ASP.NET/IIS infrastructure on '{target}' with {ep_count} endpoints. "
                "Prioritize ViewState validation, IIS handler disclosures, and authentication endpoint testing."
            )
        elif any(k in tech_str for k in ["node", "express", "react", "next", "vue", "angular"]):
            focus = "Node.js & JavaScript API Security"
            reasoning = (
                f"Detected modern JavaScript/Node.js stack on '{target}' with {ep_count} endpoints. "
                "Focus on API route authorization, prototype pollution vectors, and client-server state handling."
            )
        elif any(k in tech_str for k in ["spring", "java", "tomcat", "jboss"]):
            focus = "Java & Spring Framework Vulnerability Testing"
            reasoning = (
                f"Target '{target}' runs on Java/Spring architecture with {ep_count} endpoints. "
                "Recommended focus includes Actuator endpoints, SpEL evaluation, and deserialization safety."
            )
        elif any("graphql" in str(e).lower() for e in endpoints) or any("graphql" in str(s).lower() for s in skills):
            focus = "GraphQL Schema & Access Control Testing"
            reasoning = (
                f"Discovered GraphQL query interface on '{target}'. "
                "Recommended focus is introspecting schema definitions, testing query batching, and validating field authorization."
            )
        elif ep_count > 0:
            focus = "Endpoint Access Control & Parameter Analysis"
            reasoning = (
                f"Reconnaissance mapped {ep_count} endpoints for '{target}'. "
                "Prioritize inspecting HTTP methods, parameter validation, and authorization boundaries across discovered routes."
            )
        else:
            focus = "Attack Surface Discovery & Mapping"
            reasoning = (
                f"Initial reconnaissance phase for '{target}' with minimal surface data recorded. "
                "Focus on comprehensive host probing, technology identification, and endpoint inventory mapping."
            )

        return {
            "provider": self.provider_name,
            "target": target,
            "analysis": reasoning,
            "recommended_focus": focus,
        }

    def decide(self, context: Dict[str, Any], options: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not options:
            return {"action": "none", "reason": "No options provided."}
        chosen = options[0]
        return {
            "provider": self.provider_name,
            "decision": chosen.get("action", "unknown"),
            "option": chosen,
            "confidence": 0.88,
        }
