"""
NYX Asset Model Definition
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class Asset:
    domain: str
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "live_hosts": self.live_hosts,
            "ips": self.ips,
            "technologies": self.technologies,
            "metadata": self.metadata
        }
