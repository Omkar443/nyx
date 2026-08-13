"""
NYX Endpoint Model Definition
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    source: list[str] = field(default_factory=lambda: ["recon"])
    technology: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    priority: str = "MEDIUM"
    risk_score: int = 50

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "source": self.source,
            "technology": self.technology,
            "parameters": self.parameters,
            "priority": self.priority,
            "risk_score": self.risk_score
        }
