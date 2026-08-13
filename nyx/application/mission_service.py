"""
NYX Mission Application Service
Orchestrates autonomous security mission execution.
"""
from __future__ import annotations
from nyx.api import mission as nyx_mission


class MissionService:
    """Service facade for mission operations."""

    def init_mission(self, target: str, reset: bool = False) -> int:
        return nyx_mission.init_mission(target, reset=reset)

    def run_mission(self, target: str, step: int = 1) -> int:
        return nyx_mission.run_mission(target, step=step)
