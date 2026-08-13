"""
NYX Asset Graph Model
Represents target domain assets, subdomains, endpoints, APIs, parameters, and technology relationships.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


class AssetGraph:
    """Graph structure mapping target assets, endpoints, technologies, and parameters."""

    def __init__(self, target: str):
        self.target = target
        self.domains: List[str] = [target]
        self.subdomains: List[str] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.apis: List[Dict[str, Any]] = []
        self.parameters: List[str] = []
        self.technologies: List[Dict[str, Any]] = []
        self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()

    def add_subdomain(self, subdomain: str) -> bool:
        if subdomain not in self.subdomains:
            self.subdomains.append(subdomain)
            self.updated_at = datetime.now().isoformat()
            return True
        return False

    def add_endpoint(self, path: str, method: str = "GET", params: Optional[List[str]] = None) -> bool:
        ep = {"path": path, "method": method.upper(), "params": params or []}
        if ep not in self.endpoints:
            self.endpoints.append(ep)
            if "/api/" in path or "/v1/" in path or "graphql" in path:
                if ep not in self.apis:
                    self.apis.append(ep)
            if params:
                for p in params:
                    if p not in self.parameters:
                        self.parameters.append(p)
            self.updated_at = datetime.now().isoformat()
            return True
        return False

    def add_technology(self, name: str, category: str = "web", version: str = "") -> bool:
        tech = {"name": name, "category": category, "version": version}
        if tech not in self.technologies:
            self.technologies.append(tech)
            self.updated_at = datetime.now().isoformat()
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "domains": list(self.domains),
            "subdomains": list(self.subdomains),
            "endpoints": list(self.endpoints),
            "apis": list(self.apis),
            "parameters": list(self.parameters),
            "technologies": list(self.technologies),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetGraph:
        graph = cls(target=data.get("target", "example.com"))
        graph.domains = data.get("domains", [graph.target])
        graph.subdomains = data.get("subdomains", [])
        graph.endpoints = data.get("endpoints", [])
        graph.apis = data.get("apis", [])
        graph.parameters = data.get("parameters", [])
        graph.technologies = data.get("technologies", [])
        graph.created_at = data.get("created_at", datetime.now().isoformat())
        graph.updated_at = data.get("updated_at", datetime.now().isoformat())
        return graph
