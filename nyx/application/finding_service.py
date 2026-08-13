"""
NYX Finding Application Service
Orchestrates finding lifecycle, triage, deduplication, and report generation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from nyx.core import findings as core_findings


class FindingService:
    """Service facade for finding lifecycle and triage management."""

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
        )

    create_finding = create

    def transition(
        self, finding_id: str, new_state: str, reason: str = ""
    ) -> dict[str, Any]:
        return core_findings.transition_finding(
            finding_id=finding_id, new_state=new_state, reason=reason
        )

    transition_state = transition

    def list_findings(
        self, state: str | None = None, severity: str | None = None
    ) -> dict[str, Any]:
        return core_findings.list_findings(
            state_filter=state, severity_filter=severity
        )

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        d = core_findings.get_finding(finding_id)
        if isinstance(d, dict):
            return d
        return {"success": True, "finding": d}

    show = get_finding

    def duplicate_check(
        self, endpoint: str, parameter: str = "", vulnerability: str = ""
    ) -> dict[str, Any]:
        return core_findings.duplicate_check(
            endpoint=endpoint, parameter=parameter, vulnerability=vulnerability
        )

    def triage(self, finding_file: str) -> dict[str, Any]:
        return core_findings.triage_finding(finding_file=finding_file)

    def report(
        self, finding_id: str, platform: str = "h1", out: str | Path | None = None
    ) -> dict[str, Any]:
        res = core_findings.report_finding(
            finding_id_or_path=finding_id, platform=platform
        )
        if isinstance(res, dict) and res.get("status") == "success" and out:
            out_p = Path(out)
            out_p.write_text(res.get("draft", ""), encoding="utf-8")
            res["report_path"] = str(out_p)
        return res if isinstance(res, dict) else {"success": True, "report": res}

    report_finding = report
