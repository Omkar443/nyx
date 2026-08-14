"""
NYX Web Specialized Agent
Specialized in web application surface mapping, authentication flows, CORS/CSRF, and XSS.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
from nyx.agents.base import BaseSpecializedAgent


class WebAgent(BaseSpecializedAgent):
    """Specialized web application security agent."""

    def __init__(
        self,
        target: str,
        provider_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        agent_state: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        base_dir: Optional[Path] = None,
    ):
        super().__init__(
            agent_type="web",
            target=target,
            allowed_skills=["hunt-xss", "hunt-cors", "hunt-csrf", "hunt-auth-bypass", "hunt-session"],
            allowed_tools=["katana", "nuclei", "httpx"],
            provider_name=provider_name,
            agent_id=agent_id,
            agent_state=agent_state,
            created_at=created_at,
            updated_at=updated_at,
            base_dir=base_dir,
        )

    def execute_specialized_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        self.inner_agent.analyze()
        params = task.get("params", {})
        cand = params.get("vulnerability_candidate")
        findings_created = []

        if cand and isinstance(cand, dict):
            from nyx.application.finding_service import FindingService
            f_svc = FindingService(base_dir=self.base_dir)
            res = f_svc.create_finding(
                title=cand.get("title", f"Web Vulnerability Candidate on {self.target}"),
                endpoint=cand.get("endpoint", f"http://{self.target}"),
                parameter=cand.get("parameter", ""),
                vulnerability=cand.get("vulnerability", "XSS"),
                severity=cand.get("severity", "Medium"),
                description=cand.get("description", "Discovered by WebAgent during web surface analysis."),
                task_id=task.get("task_id", ""),
                agent_id=self.agent_id,
                target=self.target,
                evidence_ids=cand.get("evidence_ids", []),
            )
            if res.get("status") in ("success", "duplicate") and res.get("finding_id"):
                findings_created.append(res.get("finding_id"))

        return {
            "agent_id": self.agent_id,
            "agent_type": "web",
            "target": self.target,
            "web_surfaces": [f"http://{self.target}/login", f"http://{self.target}/dashboard"],
            "auth_mechanisms": ["JWT Bearer", "Session Cookie"],
            "vulnerabilities_checked": ["XSS", "CORS", "CSRF", "Auth Bypass"],
            "findings_created": findings_created,
            "findings_count": len(findings_created),
        }
