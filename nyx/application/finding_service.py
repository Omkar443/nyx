"""
NYX Finding Application Service
Orchestrates finding lifecycle, triage, deduplication, and report generation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
from nyx.core import findings as core_findings


class FindingService:
    """Service facade for finding lifecycle and triage management."""

    def __init__(self, base_dir: Optional[Path] = None, provider_name: Optional[str] = None):
        self.base_dir = base_dir
        self.provider_name = provider_name

    def create(
        self,
        title: str,
        endpoint: str = "",
        parameter: str = "",
        vulnerability: str = "",
        severity: str = "Medium",
        tag: str = "",
        description: str = "",
        tags: list[str] | None = None,
        task_id: str = "",
        agent_id: str = "",
        target: str = "",
        evidence_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        tag_str = tag or (",".join(tags) if tags else "")
        return core_findings.create_finding(
            title=title,
            endpoint=endpoint,
            parameter=parameter,
            vulnerability=vulnerability,
            severity=severity,
            tag=tag_str,
            description=description,
            task_id=task_id,
            agent_id=agent_id,
            target=target,
            evidence_ids=evidence_ids,
            base_dir=self.base_dir,
        )

    create_finding = create

    def transition(
        self, finding_id: str, new_state: str, reason: str = ""
    ) -> dict[str, Any]:
        return core_findings.transition_finding(
            finding_id=finding_id, new_state=new_state, reason=reason, base_dir=self.base_dir
        )

    transition_state = transition

    def list_findings(
        self,
        state: str | None = None,
        severity: str | None = None,
        target: str | None = None,
        base_dir: Path | None = None,
    ) -> dict[str, Any]:
        return core_findings.list_findings(
            state_filter=state,
            severity_filter=severity,
            target_filter=target,
            base_dir=base_dir or self.base_dir,
        )

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        d = core_findings.get_finding(finding_id, base_dir=self.base_dir)
        if isinstance(d, dict):
            return d
        return {"success": True, "finding": d}

    show = get_finding

    def duplicate_check(
        self, endpoint: str, parameter: str = "", vulnerability: str = ""
    ) -> dict[str, Any]:
        return core_findings.duplicate_check(
            endpoint=endpoint, parameter=parameter, vulnerability=vulnerability, base_dir=self.base_dir
        )

    def triage(self, finding_file: str) -> dict[str, Any]:
        return core_findings.triage_finding(finding_file=finding_file, base_dir=self.base_dir)

    triage_finding = triage

    def report(
        self, finding_id: str, platform: str = "h1", out: str | Path | None = None, use_ai: bool = True, provider_name: str | None = None
    ) -> dict[str, Any]:
        prov = provider_name or self.provider_name
        res = core_findings.report_finding(
            finding_id_or_path=finding_id, platform=platform, base_dir=self.base_dir, use_ai=use_ai
        )
        if isinstance(res, dict) and res.get("status") == "success" and out:
            out_p = Path(out)
            out_p.write_text(res.get("draft", ""), encoding="utf-8")
            res["report_path"] = str(out_p)
        return res if isinstance(res, dict) else {"success": True, "report": res}

    def review_evidence(
        self, finding_id: str, tool_name: str, tool_output: Any, ai_manager: Any = None, provider_name: str | None = None
    ) -> dict[str, Any]:
        return core_findings.review_finding_evidence(
            finding_id_or_data=finding_id,
            tool_name=tool_name,
            tool_output=tool_output,
            base_dir=self.base_dir,
            ai_manager=ai_manager,
            provider_name=provider_name or self.provider_name,
        )

    review_finding = review_evidence
    review = review_evidence

    def delete(self, finding_id: str) -> dict[str, Any]:
        return core_findings.delete_finding(finding_id=finding_id, base_dir=self.base_dir)

    delete_finding = delete

    def update(self, finding_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        return core_findings.update_finding(finding_id=finding_id, updates=updates, base_dir=self.base_dir)

    def enrich(self, finding_id_or_data: str | dict[str, Any], ai_manager: Any = None, provider_name: str | None = None) -> dict[str, Any]:
        return core_findings.enrich_hypothesis_description(
            finding_id_or_data=finding_id_or_data, base_dir=self.base_dir, ai_manager=ai_manager, provider_name=provider_name or self.provider_name
        )

    def enrich_all(self, ai_manager: Any = None, provider_name: str | None = None) -> list[dict[str, Any]]:
        return core_findings.enrich_all_hypotheses(base_dir=self.base_dir, ai_manager=ai_manager, provider_name=provider_name or self.provider_name)

