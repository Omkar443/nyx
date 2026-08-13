"""
NYX Runtime DOM Observer & Intelligence Graph Builder
Tracks DOM events, forms, inputs, and builds the unified Runtime Intelligence Graph.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from nyx.runtime.network import NetworkObserver
from nyx.runtime.javascript import JSObserver


class DOMObserver:
    """Tracks DOM structure, interactive forms, and constructs Runtime Intelligence Graph."""

    def __init__(self, network: Optional[NetworkObserver] = None, js: Optional[JSObserver] = None):
        self.network = network or NetworkObserver()
        self.js = js or JSObserver()
        self._forms: List[Dict[str, Any]] = []
        self._inputs: List[Dict[str, Any]] = []
        self._interesting_events: List[Dict[str, Any]] = []

    def record_form(self, action: str, method: str, inputs: List[str]) -> None:
        """Record an interactive HTML form."""
        form_item = {"action": action, "method": method.upper(), "inputs": inputs}
        self._forms.append(form_item)
        for inp in inputs:
            if inp not in [i.get("name") for i in self._inputs]:
                self._inputs.append({"name": inp, "form_action": action})

    def record_interesting_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Record a security-relevant event (e.g. CORS header reflection, auth token in URL)."""
        self._interesting_events.append({"type": event_type, "details": details})

    def get_runtime_intelligence_graph(self) -> Dict[str, Any]:
        """Construct unified Runtime Intelligence Graph."""
        reqs = self.network.logger.get_requests()
        apis = self.network.get_apis()

        # Extract unique parameter names from requests and forms
        params = list(set([i.get("name") for i in self._inputs if i.get("name")]))
        for r in reqs:
            for k in r.get("params", {}).keys():
                if k not in params:
                    params.append(k)

        # Detect technologies from response headers or script tags
        techs = []
        for r in reqs:
            hdr = {k.lower(): v for k, v in r.get("headers", {}).items()}
            if "server" in hdr and hdr["server"] not in techs:
                techs.append(hdr["server"])
            if "x-powered-by" in hdr and hdr["x-powered-by"] not in techs:
                techs.append(hdr["x-powered-by"])

        return {
            "requests": reqs,
            "apis": apis,
            "parameters": params,
            "technologies": techs,
            "interesting_events": list(self._interesting_events),
        }
