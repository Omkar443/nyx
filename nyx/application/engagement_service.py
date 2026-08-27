"""
NYX Engagement Application Service
Orchestrates engagement workspace lifecycle, state transitions, and memory persistence.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from nyx.core import engagement as core_engagement


class EngagementService:
    """Service facade for engagement workspace operations."""

    def init_engagement(self, target: str, reset: bool = False, force: bool = False) -> dict[str, Any]:
        return core_engagement.init_engagement(target=target, reset=reset, force=force)

    def get_status(self) -> dict[str, Any]:
        return core_engagement.get_engagement_status()

    def get_target(self) -> str | None:
        return core_engagement.get_engagement_target()

    def get_settings(self) -> dict[str, Any]:
        target_name = core_engagement.get_engagement_target() or ""
        from nyx.security.authorization import get_engagement_scope, get_engagement_exclusions
        scope_list = get_engagement_scope()
        exclusions = get_engagement_exclusions()
        return {
            "target": target_name,
            "scope": scope_list,
            "exclusions": exclusions,
        }

    def update_settings(self, target: str, scope: list[str] | None = None, exclusions: list[str] | None = None) -> dict[str, Any]:
        d = core_engagement._get_eng_dir(create=True)
        target_yaml = d / "target.yaml"
        scope_lines = "\n".join([f"    - \"{s}\"" for s in (scope or [target])])
        excl_lines = "\n".join([f"    - \"{e}\"" for e in (exclusions or [f"out-of-scope.{target}"])])
        
        content = f"""target:
  name: {target}
  domain: {target}
  authorization: confirmed
  scope:
{scope_lines}
  exclusions:
{excl_lines}
  start_date: "{core_engagement.datetime.date.today().isoformat()}"
"""
        target_yaml.write_text(content, encoding="utf-8")
        
        # Also update authorization.yaml if needed
        auth_yaml = d / "authorization.yaml"
        if auth_yaml.exists():
            auth_content = f"""authorized: true
target:
  - {target}
allowed:
{scope_lines}
exclusions:
{excl_lines}
"""
            auth_yaml.write_text(auth_content, encoding="utf-8")

        return {
            "status": "success",
            "target": target,
            "scope": scope or [target],
            "exclusions": exclusions or [],
            "message": "Settings updated successfully."
        }

    def set_state(self, new_state: str | None = None, mode: str | None = None, force: bool = False) -> dict[str, Any]:
        return core_engagement.set_engagement_state(new_state=new_state, mode=mode, force_state=force)

    def export_engagement(self) -> dict[str, Any]:
        return core_engagement.export_engagement()

    def add_memory(self, type_: str, value: str, source: str = "manual", priority: str = "P2", category: str = "frameworks") -> dict[str, Any]:
        return core_engagement.add_memory(type_=type_, value=value, priority=priority, category=category)

    def search_memory(self, query: str) -> dict[str, Any]:
        return core_engagement.search_memory(query=query)

    def import_burp_xml(self, xml_file: str | Path, include_out_of_scope: bool = False) -> dict[str, Any]:
        return core_engagement.import_burp_xml(xml_file=xml_file, include_out_of_scope=include_out_of_scope)
