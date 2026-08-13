"""
NYX Browser Application Service
Application facade managing browser sessions, runtime intelligence graph, auth flows, and dynamic agent tasks.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.application.base import BaseService, ServiceResult
from nyx.browser.controller import BrowserController
from nyx.runtime.dom import DOMObserver
from nyx.auth.session_manager import SessionManager
from nyx.agents.dynamic_agent import DynamicAgent


class BrowserService(BaseService):
    """Facade for browser automation, runtime network intelligence, and auth flows."""

    def __init__(self, provider_name: Optional[str] = None):
        super().__init__()
        self.provider_name = provider_name
        self.controller = BrowserController()
        self.dom_observer = DOMObserver()
        self.session_manager = SessionManager()

    def start_session(
        self,
        target: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> ServiceResult:
        """Start a new browser session."""
        session = self.controller.create_session(target=target, cookies=cookies, headers=headers)
        return self.ok(
            data=session.context.to_dict(),
            message=f"Browser session '{session.context.session_id}' started for target '{target}'.",
        )

    def list_sessions(self) -> ServiceResult:
        """List active and stored browser sessions."""
        sessions = self.controller.list_sessions()
        return self.ok(data={"count": len(sessions), "sessions": sessions}, message=f"Retrieved {len(sessions)} browser sessions.")

    def get_runtime_intelligence(self) -> ServiceResult:
        """Get the unified Runtime Intelligence Graph."""
        graph = self.dom_observer.get_runtime_intelligence_graph()
        return self.ok(data=graph, message="Retrieved Runtime Intelligence Graph.")

    def list_auth_flows(self) -> ServiceResult:
        """List recorded auth flows and session tokens."""
        flows = self.session_manager.flows.list_flows()
        sessions = self.session_manager.list_sessions()
        return self.ok(data={"flows": flows, "sessions": sessions}, message="Retrieved authentication intelligence state.")

    def run_dynamic_agent(self, target: str) -> ServiceResult:
        """Instantiate and run DynamicAgent task."""
        agent = DynamicAgent(target=target, provider_name=self.provider_name)
        out = agent.process_task({"task_id": "TSK-DYNAMIC-EXEC", "params": {"url": f"https://{target}"}})
        return self.ok(data=out, message=f"Dynamic agent executed on target '{target}'.")
