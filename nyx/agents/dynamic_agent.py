"""
NYX Dynamic Security Testing Agent
Specialized research agent executing dynamic browser automation, runtime client-side security analysis, and authenticated API testing.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.agents.base import BaseSpecializedAgent
from nyx.browser.controller import BrowserController
from nyx.runtime.dom import DOMObserver


class DynamicAgent(BaseSpecializedAgent):
    """Specialized research agent for dynamic browser testing and runtime observation."""

    def __init__(self, target: str, provider_name: Optional[str] = None):
        super().__init__(
            agent_type="dynamic",
            target=target,
            allowed_skills=["hunt-xss", "hunt-dom", "hunt-spa-api", "hunt-csrf", "hunt-cors"],
            allowed_tools=["katana", "httpx", "playwright"],
            provider_name=provider_name,
        )
        self.browser_controller = BrowserController()
        self.dom_observer = DOMObserver()

    def execute_specialized_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process dynamic testing research task using browser automation and runtime observation."""
        task_id = task.get("task_id", "TSK-DYNAMIC")
        params = task.get("params", {})
        url = params.get("url") or f"https://{self.target}"

        # 1. Create browser session
        session = self.browser_controller.create_session(target=self.target)
        nav_res = session.navigate(url)

        # 2. Record mock network traffic & DOM elements
        session.record_network_request("GET", url, {"User-Agent": "NYX-Dynamic-Agent"}, 200)
        self.dom_observer.record_form(action=f"{url}/api/login", method="POST", inputs=["username", "password"])
        self.dom_observer.record_interesting_event("dynamic_surface_discovered", {"url": url})

        # 3. Generate Runtime Intelligence Graph
        runtime_graph = self.dom_observer.get_runtime_intelligence_graph()

        # 4. Propose approval-gated dynamic verification action
        aid = self.inner_agent.approval_system.submit_for_approval({
            "action_id": "ACT-DYN-NAV",
            "tool": "playwright",
            "command": f"playwright navigate {url}",
            "args": [url],
            "reason": f"Perform dynamic DOM and client-side security analysis on '{url}'",
            "target": self.target,
        })

        output = {
            "agent_id": self.agent_id,
            "task_id": task_id,
            "target": self.target,
            "session_id": session.context.session_id,
            "navigation": nav_res,
            "proposed_action_id": aid,
            "runtime_graph": runtime_graph,
            "summary": f"Dynamic agent initialized session '{session.context.session_id}' and mapped runtime surface.",
        }
        return output

    def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return self.execute_specialized_task(task)
