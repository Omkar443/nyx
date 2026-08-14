from __future__ import annotations

class FindingDictList(dict):
    """Hybrid result dict for backward compatibility with both list[idx] and dict['findings'] callers."""
    def __init__(self, data_dict: dict, findings_list: list):
        super().__init__(data_dict)
        self._list = findings_list

    def __getitem__(self, item):
        if isinstance(item, int):
            return self._list[item]
        return super().__getitem__(item)

    def __iter__(self):
        return iter(self._list)

    def __len__(self):
        return len(self._list)

"""
NYX Core Findings & Lifecycle Module
Canonical business logic for finding CRUD, timeline tracking, state machine transitions, deduplication, triage, and reporting.
"""

import datetime
import json
import os
import re
from pathlib import Path
from typing import Any

from nyx.infrastructure.filesystem import REPO_ROOT, _get_eng_dir
from nyx.infrastructure.urls import normalize_url
from nyx.security.authorization import _sanitize_text_content

ALLOWED_FINDING_TRANSITIONS = {
    "HYPOTHESIS": ["TRIAGED", "REJECTED"],
    "TRIAGED": ["VALIDATED", "REJECTED"],
    "VALIDATED": ["REPORTED", "REJECTED"],
    "REPORTED": ["REJECTED"],
    "REJECTED": ["HYPOTHESIS"],
}

TRIAGE_QUESTIONS = [
    (
        "Q1",
        "Can an attacker use this RIGHT NOW with a real HTTP request?",
        ["curl ", "POST ", "GET ", "HTTP/1.1", "PUT ", "DELETE ", "PATCH "],
    ),
    (
        "Q2",
        "Is the impact on the program's accepted-impact list?",
        [
            "impact:",
            "severity:",
            "p1",
            "p2",
            "p3",
            "p4",
            "critical",
            "high",
            "medium",
            "low",
        ],
    ),
    (
        "Q3",
        "Is the asset in scope?",
        ["scope", "in-scope", "in scope", "target:", "asset:"],
    ),
    (
        "Q4",
        "Does it work without privileged access an attacker can't get?",
        [
            "attacker",
            "unauthenticated",
            "user-role",
            "low-priv",
            "any user",
            "session",
        ],
    ),
    (
        "Q5",
        "Is this not already known or documented behavior?",
        [
            "disclosed-reports",
            "h1 hacktivity",
            "not duplicate",
            "novel",
            "first reported",
            "previously unknown",
            "previously",
        ],
    ),
    (
        "Q6",
        "Can impact be proved beyond 'technically possible'?",
        [
            "leaked",
            "exfiltrated",
            "rce",
            "data:",
            "credential",
            "session-id",
            "cookie:",
            "admin email",
            "production",
            "oob callback",
            "interactsh",
        ],
    ),
    (
        "Q7",
        "Is this not on the never-submit list?",
        [
            "self-xss",
            "rate-limit only",
            "click-jacking",
            "csrf on logout",
            "missing security headers",
        ],
    ),
]


def _sync_findings_index(d: Path):
    f_dir = d / "findings"
    findings_file = d / "findings.json"
    if not f_dir.exists():
        return

    items = []
    for sub in sorted(f_dir.glob("FH-*")):
        f_json = sub / "finding.json"
        if f_json.exists():
            try:
                data = json.loads(f_json.read_text(encoding="utf-8"))
                items.append(data)
            except Exception:
                pass

    findings_file.write_text(json.dumps(items, indent=2), encoding="utf-8")


def _generate_finding_id(eng_dir: Path, year: int | None = None) -> str:
    if year is None:
        year = datetime.datetime.now().year
    f_root = eng_dir / "findings"
    max_seq = 0
    if f_root.exists():
        for sub in f_root.glob(f"FH-{year}-*"):
            seq_str = sub.name.split("-")[-1]
            if seq_str.isdigit():
                max_seq = max(max_seq, int(seq_str))
    return f"FH-{year}-{max_seq + 1:03d}"


def get_finding(finding_id: str, base_dir: Path | None = None) -> dict[str, Any] | None:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return None
    f_file = d / "findings" / finding_id / "finding.json"
    if f_file.exists():
        try:
            return json.loads(f_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    findings_file = d / "findings.json"
    if findings_file.exists():
        try:
            stored = json.loads(findings_file.read_text(encoding="utf-8"))
            for f in stored:
                if f.get("finding_id") == finding_id:
                    return f
        except Exception:
            pass
    return None


def create_finding(
    title: str,
    endpoint: str = "",
    parameter: str = "",
    vulnerability: str = "",
    severity: str = "Medium",
    tag: str = "",
    description: str = "",
    task_id: str = "",
    agent_id: str = "",
    target: str = "",
    evidence_ids: list[str] | None = None,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {
            "status": "error",
            "message": "No active engagement workspace found.",
        }

    # Check duplicate finding first
    dup = duplicate_check(endpoint=endpoint, parameter=parameter, vulnerability=vulnerability, base_dir=base_dir)
    if dup.get("is_duplicate"):
        existing_f = dup.get("existing_finding", {})
        return {
            "status": "duplicate",
            "is_duplicate": True,
            "finding_id": existing_f.get("finding_id"),
            "finding": existing_f,
            "message": f"Duplicate finding '{existing_f.get('finding_id')}' already recorded.",
        }

    fid = _generate_finding_id(d)
    now_str = datetime.datetime.now().isoformat()

    san_title, _ = _sanitize_text_content(title)
    san_ep_raw, _ = _sanitize_text_content(endpoint)
    san_ep = normalize_url(san_ep_raw)
    san_param, _ = _sanitize_text_content(parameter)
    san_vuln, _ = _sanitize_text_content(vulnerability)
    san_desc, _ = _sanitize_text_content(description)

    fdata = {
        "finding_id": fid,
        "task_id": task_id,
        "agent_id": agent_id,
        "target": target or (san_ep.split("/")[2] if "://" in san_ep else san_ep),
        "title": san_title,
        "severity": severity,
        "status": "HYPOTHESIS",
        "endpoint": san_ep,
        "parameter": san_param,
        "vulnerability": san_vuln,
        "tag": tag,
        "description": san_desc,
        "evidence_ids": evidence_ids or [],
        "created_at": now_str,
        "updated_at": now_str,
    }

    f_dir = d / "findings" / fid
    f_dir.mkdir(parents=True, exist_ok=True)
    (f_dir / "finding.json").write_text(
        json.dumps(fdata, indent=2), encoding="utf-8"
    )

    tdata = [
        {
            "timestamp": now_str,
            "event": "created",
            "from": None,
            "to": "HYPOTHESIS",
            "reason": "Finding recorded",
            "source": "nyx",
        }
    ]
    (f_dir / "timeline.json").write_text(
        json.dumps(tdata, indent=2), encoding="utf-8"
    )
    (f_dir / "hypotheses.json").write_text("[]", encoding="utf-8")

    _sync_findings_index(d)

    return {"status": "success", "finding_id": fid, "finding": fdata}


def transition_finding(
    finding_id: str,
    new_state: str,
    reason: str = "",
    base_dir: Path | None = None,
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {
            "status": "error",
            "message": "No active engagement workspace found.",
        }

    f_dir = d / "findings" / finding_id
    f_json = f_dir / "finding.json"
    if not f_json.exists():
        return {
            "status": "error",
            "message": f"Finding '{finding_id}' not found in engagement workspace.",
        }

    fdata = json.loads(f_json.read_text(encoding="utf-8"))
    curr_state = fdata.get("status", "HYPOTHESIS")
    allowed = ALLOWED_FINDING_TRANSITIONS.get(curr_state, [])

    if new_state not in allowed:
        return {
            "status": "error",
            "code": "INVALID_TRANSITION",
            "curr_state": curr_state,
            "requested_state": new_state,
            "allowed": allowed,
            "message": f"Invalid finding transition ({curr_state} -> {new_state}).",
        }

    now_str = datetime.datetime.now().isoformat()
    fdata["status"] = new_state
    fdata["updated_at"] = now_str
    f_json.write_text(json.dumps(fdata, indent=2), encoding="utf-8")

    timeline_p = f_dir / "timeline.json"
    tdata = (
        json.loads(timeline_p.read_text(encoding="utf-8"))
        if timeline_p.exists()
        else []
    )
    tdata.append(
        {
            "timestamp": now_str,
            "event": "transition",
            "from": curr_state,
            "to": new_state,
            "reason": _sanitize_text_content(reason),
            "source": "nyx",
        }
    )
    timeline_p.write_text(json.dumps(tdata, indent=2), encoding="utf-8")

    _sync_findings_index(d)

    return {
        "status": "success",
        "finding_id": finding_id,
        "old_state": curr_state,
        "new_state": new_state,
        "reason": reason,
    }


def list_findings(
    state_filter: str | None = None,
    severity_filter: str | None = None,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {
            "status": "error",
            "message": "No active engagement workspace found.",
        }

    _sync_findings_index(d)
    findings_file = d / "findings.json"
    if not findings_file.exists():
        return {"status": "success", "findings": []}

    try:
        findings = json.loads(findings_file.read_text(encoding="utf-8"))
    except Exception as e:
        return {"status": "error", "message": f"Malformed findings.json: {e}"}

    if state_filter:
        findings = [
            f
            for f in findings
            if f.get("status", "").upper() == state_filter.upper()
        ]
    if severity_filter:
        findings = [
            f
            for f in findings
            if f.get("severity", "").lower() == severity_filter.lower()
        ]

    return FindingDictList({"status": "success", "findings": findings}, findings)


def duplicate_check(
    endpoint: str,
    parameter: str = "",
    vulnerability: str = "",
    base_dir: Path | None = None,
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    findings_file = d / "findings.json"

    ep = normalize_url(endpoint or "").lower()
    param = (parameter or "").strip().lower()
    vuln = (vulnerability or "").strip().lower()

    if not findings_file.exists():
        return {"status": "pass", "is_duplicate": False}

    try:
        findings = json.loads(findings_file.read_text(encoding="utf-8"))
    except Exception as e:
        return {"status": "error", "message": f"Malformed findings.json: {e}"}

    for f in findings:
        f_ep = normalize_url(str(f.get("endpoint", ""))).lower()
        f_param = str(f.get("parameter", "")).strip().lower()
        f_vuln = str(f.get("vulnerability", "")).strip().lower()

        if f_ep == ep and f_param == param and f_vuln == vuln:
            return {
                "status": "duplicate",
                "is_duplicate": True,
                "existing_finding": f,
            }

    return {"status": "pass", "is_duplicate": False}


def triage_finding(
    finding_file: str, base_dir: Path | None = None
) -> dict[str, Any]:
    finding_path = Path(finding_file)
    if not finding_path.exists():
        return {
            "status": "error",
            "message": f"Finding file not found: {finding_path}",
        }

    text = finding_path.read_text(encoding="utf-8").lower()
    answers = []
    for qid, question, signals in TRIAGE_QUESTIONS:
        hit = any(s.lower() in text for s in signals)
        if qid == "Q7":
            answer = "NO — finding matches never-submit category" if hit else "YES"
            ok = not hit
        else:
            answer = (
                "YES — evidence found"
                if hit
                else "NO — no supporting evidence in finding"
            )
            ok = hit
        answers.append(
            {"id": qid, "question": question, "answer": answer, "ok": ok}
        )

    fail_qs = [q["id"] for q in answers if not q["ok"]]
    if not fail_qs:
        verdict = "PASS"
    elif len(fail_qs) == 1 and fail_qs[0] in ("Q2", "Q5"):
        verdict = "DOWNGRADE"
    else:
        verdict = "KILL"

    passed_count = len([q for q in answers if q["ok"]])
    status_str = "PASSED" if verdict == "PASS" else "FAILED"
    questions = [
        {"id": q["id"], "question": q["question"], "passed": q["ok"], "answer": q["answer"]}
        for q in answers
    ]

    return {
        "status": status_str,
        "passed_count": passed_count,
        "verdict": verdict,
        "questions": questions,
        "answers": answers,
        "failed_questions": fail_qs,
    }


def parse_finding_metadata(text: str) -> dict[str, str]:
    md = {
        "title": "",
        "severity": "Medium",
        "asset": "",
        "endpoint": "",
        "summary": "",
        "steps": "",
        "impact": "",
        "remediation": "",
    }
    m = re.match(r"^---\n(.*?)\n---\n(.*)", text, re.S)
    body = text
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                md[k.strip().lower()] = v.strip().strip('"').strip("'")
        body = m.group(2)
    for key, pat in [
        ("summary", r"##\s*(?:summary|description)\s*\n(.+?)(?=\n##|\Z)"),
        (
            "steps",
            r"##\s*(?:steps|reproduction|reproduce|poc)(?:\s+steps|\s+to\s+reproduce)?\s*\n(.+?)(?=\n##|\Z)",
        ),
        ("impact", r"##\s*impact\s*\n(.+?)(?=\n##|\Z)"),
        (
            "remediation",
            r"##\s*(?:remediation|fix|mitigation)\s*\n(.+?)(?=\n##|\Z)",
        ),
    ]:
        m = re.search(pat, body, re.I | re.S)
        if m and not md.get(key):
            md[key] = m.group(1).strip()
    if not md["title"]:
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("# "):
                md["title"] = line[2:].strip()
                break
    return md


def render_report(md: dict, platform: str) -> str:
    title = md.get("title") or "Untitled finding"
    severity = md.get("severity") or "Medium"
    summary = md.get("summary") or "(fill in)"
    steps = md.get("steps") or "(fill in — curl commands per step)"
    impact = (
        md.get("impact") or "(fill in — concrete dollar / PII / state impact)"
    )
    remediation = md.get("remediation") or "(fill in)"
    asset = md.get("asset") or md.get("endpoint") or "(fill in)"
    user = os.environ.get("USER", "researcher")
    today = datetime.date.today().isoformat()

    if platform == "bugcrowd":
        return f"""# {title}

**Bug type (VRT):** _to be filled in — pick the closest match from VRT 1.x and include the manual override paragraph below if defaults underrate impact._
**Severity:** {severity}
**Asset:** {asset}
**Date:** {today}

## Severity request

The closest VRT category for this finding is _<VRT-path>_, which Bugcrowd defaults to **<default-severity>**. **I am requesting evaluation at {severity}** for the following reasons:

1. _<concrete impact reason>_
2. _<exploit complexity reason>_
3. _<chained-finding cross-reference if applicable>_

## Summary
{summary}

## Steps to reproduce
{steps}

## Impact
{impact}

## Suggested remediation
{remediation}

## Researcher account
- Bugcrowd handle: _<your-handle>_
- Test account email: _<your-alias>@bugcrowdninja.com_
"""

    if platform == "immunefi":
        slug = re.sub(r"[^a-z0-9]+", "_", title.lower())
        return f"""# {title}

**Severity:** {severity}
**Chain ID / Contract:** {asset}
**Date:** {today}

## Summary
{summary}

## Vulnerability Details
{impact}

## Steps to reproduce (Foundry PoC required)
```bash
forge test --match-test test_{slug} -vvv
```
{steps}

## Proof of Concept
_Attach the Foundry test file producing the exploit._

## Suggested remediation
{remediation}
"""

    common = f"""# {title}

**Severity:** {severity}
**Asset:** {asset}
**Reporter:** {user}
**Date:** {today}

## Summary
{summary}

## Steps to reproduce
{steps}

## Impact
{impact}

## Suggested remediation
{remediation}
"""

    if platform == "intigriti":
        return (
            common
            + "\n## CVSS 3.1 vector\n`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (fill in)\n"
        )

    return common


def report_finding(
    finding_id_or_path: str,
    platform: str = "h1",
    base_dir: Path | None = None,
) -> dict[str, Any]:
    md = {}
    finding_path = Path(finding_id_or_path)

    d = _get_eng_dir(create=False, base_dir=base_dir)
    findings_file = d / "findings.json"
    if findings_file.exists():
        try:
            stored = json.loads(findings_file.read_text(encoding="utf-8"))
            for f in stored:
                if (
                    f.get("finding_id") == finding_id_or_path
                    or f.get("title") == finding_id_or_path
                ):
                    md = {
                        "title": f.get("title", ""),
                        "severity": f.get("severity", "Medium"),
                        "asset": f.get("endpoint", ""),
                        "endpoint": f.get("endpoint", ""),
                        "summary": f.get("title", ""),
                        "steps": f.get("evidence", "(fill in steps)"),
                        "impact": f.get("vulnerability", "(fill in impact)"),
                        "remediation": f.get(
                            "remediation", "(fill in remediation)"
                        ),
                    }
                    break
        except Exception:
            pass

    if not md and finding_path.exists():
        md = parse_finding_metadata(finding_path.read_text(encoding="utf-8"))
    elif not md:
        return {
            "status": "error",
            "message": f"Finding '{finding_id_or_path}' not found as file or in .engagement/findings.json",
        }

    draft = render_report(md, platform)
    return {
        "status": "success",
        "platform": platform,
        "metadata": md,
        "draft": draft,
    }


# Function aliases for backward compatibility and test suites
create = create_finding
list = list_findings
transition = transition_finding
triage = triage_finding
report = report_finding