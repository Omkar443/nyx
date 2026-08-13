"""
NYX Skill Application Service
Orchestrates skill discovery, listing, and inspection.
"""
from __future__ import annotations
from nyx.application.base import BaseService, ServiceResult
from nyx.core import skills as nyx_skills


class SkillService(BaseService):
    """Service facade for security skill catalog operations."""

    def list_skills(self, category: str | None = None) -> list[dict]:
        """Direct list returned for legacy compatibility; see get_skills_result() for ServiceResult."""
        return nyx_skills.list_skills(category=category)

    def get_skills_result(self, category: str | None = None) -> ServiceResult:
        """Structured ServiceResult container for skill catalog listing."""
        try:
            sk_list = nyx_skills.list_skills(category=category)
            return self.ok(data={"skills": sk_list, "count": len(sk_list)}, message=f"Retrieved {len(sk_list)} skills.")
        except Exception as ex:
            return self.fail(message=f"Error listing skills: {ex}", error_code="SKILL_ERROR")

    def get_skill(self, name: str) -> dict | None:
        return nyx_skills.get_skill(name)

    def get_skill_result(self, name: str) -> ServiceResult:
        try:
            sk = nyx_skills.get_skill(name)
            if sk:
                return self.ok(data=sk, message=f"Found skill '{name}'.")
            return self.fail(message=f"Skill '{name}' not found.", error_code="NOT_FOUND")
        except Exception as ex:
            return self.fail(message=f"Error reading skill '{name}': {ex}", error_code="SKILL_ERROR")
