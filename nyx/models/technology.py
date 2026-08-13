"""
NYX Technology Model Definition
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class Technology:
    name: str
    category: str = "Framework"
    version: str | None = None
    confidence: float = 1.0
    detected_headers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
            "detected_headers": self.detected_headers
        }
