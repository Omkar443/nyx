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

import builtins
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
    "HYPOTHESIS": ["TRIAGED", "VALIDATED", "CONFIRMED", "REJECTED"],
    "TRIAGED": ["VALIDATED", "CONFIRMED", "REJECTED"],
    "VALIDATED": ["CONFIRMED", "REPORTED", "REJECTED", "HYPOTHESIS"],
    "CONFIRMED": ["REPORTED", "REJECTED", "HYPOTHESIS"],
    "REPORTED": ["REJECTED"],
    "REJECTED": ["HYPOTHESIS", "TRIAGED"],
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
            "exposure",
            "attack surface",
            "unauthorized",
            "file disclosure",
            "access",
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
            "missing hsts",
            "missing-hsts",
            "hsts",
        ],
    ),
]


import threading
_FINDINGS_LOCK = threading.RLock()


def _sync_findings_index(d: Path):
    with _FINDINGS_LOCK:
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
    res = None
    f_file = d / "findings" / finding_id / "finding.json"
    if f_file.exists():
        try:
            res = json.loads(f_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    if res is None:
        findings_file = d / "findings.json"
        if findings_file.exists():
            try:
                stored = json.loads(findings_file.read_text(encoding="utf-8"))
                for f in stored:
                    if f.get("finding_id") == finding_id:
                        res = f
                        break
            except Exception:
                pass
    if res and isinstance(res, dict):
        if "status" in res and "state" not in res:
            res["state"] = res["status"]
        elif "state" in res and "status" not in res:
            res["status"] = res["state"]
    return res


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
    with _FINDINGS_LOCK:
        d = _get_eng_dir(create=False, base_dir=base_dir)
        if not d.exists():
            return {
                "status": "error",
                "message": "No active engagement workspace found.",
            }

        # Check duplicate finding first (synchronized under lock)
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
    target_filter: str | None = None,
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
    if target_filter:
        clean_t = target_filter.lower().replace("http://", "").replace("https://", "").split(":")[0]
        findings = [
            f
            for f in findings
            if clean_t in (f.get("target", "") or "").lower()
            or clean_t in (f.get("endpoint", "") or "").lower()
        ]

    return FindingDictList({"status": "success", "findings": findings}, findings)


def delete_finding(finding_id: str, base_dir: Path | None = None) -> dict[str, Any]:
    """Deletes a finding record and its directory from the engagement workspace."""
    with _FINDINGS_LOCK:
        d = _get_eng_dir(create=False, base_dir=base_dir)
        if not d.exists():
            return {"status": "error", "message": "No active engagement workspace found."}

        fid = (finding_id or "").strip().upper()
        f_dir = d / "findings" / fid
        deleted = False
        if f_dir.exists():
            import shutil
            shutil.rmtree(f_dir, ignore_errors=True)
            deleted = True

        findings_file = d / "findings.json"
        if findings_file.exists():
            try:
                findings_arr = json.loads(findings_file.read_text(encoding="utf-8"))
                if isinstance(findings_arr, list):
                    new_arr = [f for f in findings_arr if f.get("finding_id") != fid]
                    if len(new_arr) != len(findings_arr):
                        deleted = True
                    findings_file.write_text(json.dumps(new_arr, indent=2), encoding="utf-8")
            except Exception:
                pass

        _sync_findings_index(d)
        if deleted:
            return {"status": "success", "message": f"Finding '{fid}' deleted."}
        return {"status": "error", "message": f"Finding '{fid}' not found."}


def duplicate_check(
    endpoint: str,
    parameter: str = "",
    vulnerability: str = "",
    base_dir: Path | None = None,
) -> dict[str, Any]:
    with _FINDINGS_LOCK:
        d = _get_eng_dir(create=False, base_dir=base_dir)
        if not d.exists():
            return {"status": "pass", "is_duplicate": False}

        ep = normalize_url(endpoint or "").lower()
        param = (parameter or "").strip().lower()
        vuln = (vulnerability or "").strip().lower()

        findings_map: dict[str, dict] = {}

        # 1. Check directory ground-truth (individual finding.json files)
        f_dir = d / "findings"
        if f_dir.exists():
            for sub in f_dir.glob("FH-*"):
                f_json = sub / "finding.json"
                if f_json.exists():
                    try:
                        data = json.loads(f_json.read_text(encoding="utf-8"))
                        if isinstance(data, dict) and data.get("finding_id"):
                            findings_map[data["finding_id"]] = data
                    except Exception:
                        pass

        # 2. Check findings.json index
        findings_file = d / "findings.json"
        if findings_file.exists():
            try:
                findings_arr = json.loads(findings_file.read_text(encoding="utf-8"))
                if isinstance(findings_arr, list):
                    for f in findings_arr:
                        if isinstance(f, dict) and f.get("finding_id"):
                            findings_map[f["finding_id"]] = f
            except Exception:
                pass

        for f in findings_map.values():
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


def generate_ai_report_content(md: dict, platform: str, base_dir: Path | None = None) -> tuple[bool, dict]:
    """Invoke AI provider to draft tailored technical sections for a vulnerability report."""
    try:
        from nyx.ai.manager import AIManager
        ai_mgr = AIManager()

        status_val = md.get("status", "HYPOTHESIS").upper()
        finding_id = md.get("finding_id", "FH-UNKNOWN")
        title = md.get("title", "")
        endpoint = md.get("endpoint") or md.get("asset", "")
        param = md.get("parameter", "")
        vuln = md.get("vulnerability", "")
        severity = md.get("severity", "Medium")
        desc = md.get("description", "")
        evidence_text = md.get("evidence_summary", "")
        techs = md.get("technologies", [])

        prompt = (
            f"You are a Senior Security Researcher writing a technical vulnerability submission report for {platform.capitalize()}.\n"
            "Author realistic, technically accurate, and structured report sections for this security finding.\n\n"
            f"Finding Metadata:\n"
            f"- Finding ID: {finding_id}\n"
            f"- Title: {title}\n"
            f"- Target Asset / Endpoint: {endpoint}\n"
            f"- Parameter: {param or 'N/A'}\n"
            f"- Vulnerability Type: {vuln}\n"
            f"- Severity: {severity}\n"
            f"- Finding Lifecycle Status: {status_val}\n"
            f"- Classification & Context: {desc}\n"
            f"- Evidence Summary: {evidence_text or 'Preliminary surface classification / HTTP route discovery'}\n"
            f"- Detected Stack: {', '.join(techs) if techs else 'Web Application'}\n\n"
            "CRITICAL REPORTING CONSTRAINTS:\n"
            "1. Ground all steps and explanations specifically in the provided endpoint, parameter, and technology context (e.g. PHP LFI parameter handling, file upload multipart boundaries, etc.). Do not output generic placeholder brackets.\n"
            f"2. STATUS INTEGRITY: The current status is '{status_val}'. If status is 'HYPOTHESIS' or 'VALIDATING' (unconfirmed), the summary and impact MUST explicitly clarify that this finding represents an identified vulnerable attack surface or theoretical vector pending active PoC confirmation — do NOT hallucinate or claim confirmed remote code execution, database exfiltration, or successful exploitation.\n"
            "3. If status is 'CONFIRMED' or verified evidence is present, describe the confirmed exploit flow and verified impact.\n"
            "4. Output ONLY a valid JSON object with the following keys:\n"
            "{\n"
            '  "vrt_category": "<suggested Bugcrowd VRT category or vulnerability category>",\n'
            '  "severity_justification": "<concise 2-3 sentence explanation justifying the requested severity score>",\n'
            '  "summary": "<2-3 paragraph technical summary explaining the vulnerability, affected asset/parameter, and architecture>",\n'
            '  "steps_to_reproduce": "<detailed step-by-step reproduction instructions with exact HTTP request/curl or browser actions for this endpoint>",\n'
            '  "impact": "<technical impact assessment detailing the security risks if exploited, clearly reflecting finding status>",\n'
            '  "remediation": "<actionable, language/framework-specific code and configuration fix recommendations>"\n'
            "}"
        )

        resp_text = ai_mgr.generate(prompt, options={"max_completion_tokens": 3000})
        if resp_text:
            m = re.search(r"\{.*\}", resp_text, re.DOTALL)
            if m:
                raw_json = m.group(0)
                data = None
                try:
                    data = json.loads(raw_json)
                except Exception:
                    try:
                        data = json.loads(raw_json, strict=False)
                    except Exception:
                        pass
                if isinstance(data, dict) and data.get("summary") and data.get("impact"):
                    return True, data
    except Exception as ex:
        import logging
        logging.getLogger("nyx.core.findings").warning("[REPORT] AI report generation failed (%s) — falling back to deterministic template", ex)

    return False, {}


def render_report(md: dict, platform: str, ai_content: dict | None = None, is_fallback: bool = False) -> str:
    title = md.get("title") or "Untitled finding"
    severity = md.get("severity") or "Medium"
    asset = md.get("asset") or md.get("endpoint") or "(fill in)"
    user = os.environ.get("USER", "researcher")
    today = datetime.date.today().isoformat()

    if ai_content:
        vrt_category = ai_content.get("vrt_category") or "Server-Side Injection > File Inclusion"
        sev_just = ai_content.get("severity_justification") or f"Requested evaluation at {severity} based on technical analysis of the attack surface."
        summary = ai_content.get("summary") or md.get("summary", "")
        steps = ai_content.get("steps_to_reproduce") or md.get("steps", "")
        impact = ai_content.get("impact") or md.get("impact", "")
        remediation = ai_content.get("remediation") or md.get("remediation", "")
    else:
        vrt_category = "_<VRT-path>_"
        sev_just = (
            f"The closest VRT category for this finding is _<VRT-path>_, which Bugcrowd defaults to **<default-severity>**. "
            f"**I am requesting evaluation at {severity}** for the following reasons:\n\n"
            f"1. _<concrete impact reason>_\n"
            f"2. _<exploit complexity reason>_\n"
            f"3. _<chained-finding cross-reference if applicable>_"
        )
        summary = md.get("summary") or "(fill in)"
        steps = md.get("steps") or "(fill in — curl commands per step)"
        impact = md.get("impact") or "(fill in — concrete dollar / PII / state impact)"
        remediation = md.get("remediation") or "(fill in)"

    fallback_banner = ""
    if is_fallback:
        fallback_banner = "> [!NOTE]\n> **Fallback Report Template**: AI drafting was unavailable; please review and populate remaining placeholders manually.\n\n"

    if platform == "bugcrowd":
        return f"""{fallback_banner}# {title}

**Bug type (VRT):** {vrt_category}
**Severity:** {severity}
**Asset:** {asset}
**Date:** {today}

## Severity request

{sev_just}

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
        return f"""{fallback_banner}# {title}

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

    common = f"""{fallback_banner}# {title}

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
    platform: str = "bugcrowd",
    base_dir: Path | None = None,
    use_ai: bool = True,
) -> dict[str, Any]:
    md = {}
    finding_path = Path(finding_id_or_path)

    d = _get_eng_dir(create=False, base_dir=base_dir)
    findings_file = d / "findings.json"
    raw_finding = {}
    if findings_file.exists():
        try:
            stored = json.loads(findings_file.read_text(encoding="utf-8"))
            for f in stored:
                if (
                    f.get("finding_id") == finding_id_or_path
                    or f.get("title") == finding_id_or_path
                ):
                    raw_finding = f
                    md = {
                        "finding_id": f.get("finding_id", ""),
                        "title": f.get("title", ""),
                        "severity": f.get("severity", "Medium"),
                        "status": f.get("status", "HYPOTHESIS"),
                        "asset": f.get("endpoint", ""),
                        "endpoint": f.get("endpoint", ""),
                        "parameter": f.get("parameter", ""),
                        "vulnerability": f.get("vulnerability", ""),
                        "description": f.get("description", ""),
                        "summary": f.get("description") or f.get("title", ""),
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
        raw_finding = md
    elif not md:
        return {
            "status": "error",
            "message": f"Finding '{finding_id_or_path}' not found as file or in .engagement/findings.json",
        }

    # Enrich with tech stack & evidence summary
    tech_stack = []
    tech_file = d / "technologies.json"
    if tech_file.exists():
        try:
            t_data = json.loads(tech_file.read_text(encoding="utf-8"))
            tech_stack = t_data if isinstance(t_data, list) else t_data.get("technologies", [])
        except Exception:
            pass
    md["technologies"] = tech_stack

    ev_summaries = []
    evidence_ids = raw_finding.get("evidence_ids") or []
    ev_dir = d / "evidence"
    if ev_dir.exists():
        for eid in evidence_ids:
            ef = ev_dir / f"{eid}.json"
            if ef.exists():
                try:
                    ev_obj = json.loads(ef.read_text(encoding="utf-8"))
                    ev_summaries.append(str(ev_obj.get("data") or ev_obj))
                except Exception:
                    pass
    if ev_summaries:
        md["evidence_summary"] = "\n".join(ev_summaries)

    ai_generated = False
    ai_content = None
    if use_ai:
        ok, ai_data = generate_ai_report_content(md, platform, base_dir=base_dir)
        if ok and ai_data:
            ai_generated = True
            ai_content = ai_data

    draft = render_report(md, platform, ai_content=ai_content, is_fallback=not ai_generated)
    return {
        "status": "success",
        "platform": platform,
        "metadata": md,
        "draft": draft,
        "ai_generated": ai_generated,
        "fallback": not ai_generated,
    }


def review_finding_evidence(
    finding_id_or_data: str | dict[str, Any],
    tool_name: str,
    tool_output: str | dict[str, Any],
    base_dir: Path | None = None,
) -> dict[str, Any]:
    """Submits raw tool validation output to AI provider to evaluate whether evidence confirms the finding."""
    d = _get_eng_dir(create=False, base_dir=base_dir)
    fdata = {}
    fid = ""

    if isinstance(finding_id_or_data, dict):
        fdata = finding_id_or_data
        fid = fdata.get("finding_id", "")
    else:
        fid = str(finding_id_or_data)
        if d.exists():
            f_file = d / "findings" / fid / "finding.json"
            if f_file.exists():
                try:
                    fdata = json.loads(f_file.read_text(encoding="utf-8"))
                except Exception:
                    pass
            if not fdata:
                idx_file = d / "findings.json"
                if idx_file.exists():
                    try:
                        stored = json.loads(idx_file.read_text(encoding="utf-8"))
                        for item in stored:
                            if item.get("finding_id") == fid:
                                fdata = item
                                break
                    except Exception:
                        pass

    vuln_type = fdata.get("vulnerability") or fdata.get("title") or "Vulnerability"
    endpoint = fdata.get("endpoint") or fdata.get("target") or "target endpoint"
    param = fdata.get("parameter") or ""

    # Format tool output representation concisely for prompt budget
    if isinstance(tool_output, builtins.dict):
        res_list = tool_output.get("data", {}).get("results") if isinstance(tool_output.get("data"), builtins.dict) else tool_output.get("results")
        vulns = tool_output.get("vulnerabilities") or tool_output.get("raw_findings") or []
        if res_list and isinstance(res_list, builtins.list):
            sample_results = res_list[:10]
            raw_out_str = json.dumps({"matched_count": len(res_list), "sample_results": sample_results}, indent=2)
        elif vulns and isinstance(vulns, builtins.list):
            raw_out_str = json.dumps({"vulnerabilities_count": len(vulns), "vulnerabilities": vulns[:10]}, indent=2)
        else:
            out_sample = {k: v for k, v in tool_output.items() if k not in ("data", "artifacts")}
            if "stdout" in tool_output:
                out_sample["stdout"] = (tool_output["stdout"] or "")[:2000]
            raw_out_str = json.dumps(out_sample, indent=2)
    elif isinstance(tool_output, builtins.list):
        raw_out_str = json.dumps(tool_output[:10], indent=2)
    else:
        raw_out_str = str(tool_output)

    if len(raw_out_str) > 3000:
        raw_out_str = raw_out_str[:3000] + "\n... [truncated for token budget]"

    prompt = f"""You are a Senior Security Researcher and Vulnerability Triager evaluating empirical tool verification results.
Review the following raw tool execution output claiming a match for:
- Vulnerability: {vuln_type}
- Endpoint: {endpoint}
- Parameter: {param}
- Validation Tool: {tool_name}

Tool Output / Evidence:
```
{raw_out_str}
```

Critical Evaluation Guidelines:
1. Does this evidence genuinely prove the vulnerability (e.g. actual file contents leaked like /etc/passwd or access.log entries, SQL syntax error/delay confirmed, SSRF callback received, successful authentication bypass)?
2. Or could it be a false positive (e.g. generic HTTP 200 returned for any input, static default page, reflected input without execution, common wordlist match without unauthorized access)?
3. If the evidence is ambiguous, partial, or shows potential leads without conclusive empirical proof, mark as NEEDS_MORE_EVIDENCE.

Respond ONLY in the following format:
VERDICT: [CONFIRMED | LIKELY_FALSE_POSITIVE | NEEDS_MORE_EVIDENCE]
REASONING: <concise technical justification explaining why this verdict was reached based on the empirical evidence>
"""

    verdict = "NEEDS_MORE_EVIDENCE"
    reasoning = "AI review did not return a conclusive verdict."

    try:
        from nyx.ai.manager import AIProviderManager
        ai_mgr = AIProviderManager()
        resp_text = ai_mgr.generate(prompt, options={"max_completion_tokens": 800})
        if resp_text:
            v_match = re.search(r"VERDICT:\s*\[?(CONFIRMED|LIKELY_FALSE_POSITIVE|NEEDS_MORE_EVIDENCE)\]?", resp_text, re.IGNORECASE)
            r_match = re.search(r"REASONING:\s*(.*)", resp_text, re.DOTALL | re.IGNORECASE)
            if v_match:
                verdict = v_match.group(1).upper()
            if r_match:
                reasoning = r_match.group(1).strip()
            elif not r_match:
                reasoning = resp_text.strip()
    except Exception as ex:
        import logging
        logging.getLogger("nyx.core.findings").warning("[AI-REVIEW] AI review failed (%s); defaulting to NEEDS_MORE_EVIDENCE", ex)
        reasoning = f"AI review provider error: {ex}. Retaining hypothesis status."

    if verdict == "CONFIRMED":
        new_status = "CONFIRMED"
    elif verdict == "LIKELY_FALSE_POSITIVE":
        new_status = "REJECTED"
    else:
        new_status = "HYPOTHESIS"

    if d.exists() and fid:
        with _FINDINGS_LOCK:
            f_dir = d / "findings" / fid
            f_json = f_dir / "finding.json"
            if f_json.exists():
                try:
                    f_cur = json.loads(f_json.read_text(encoding="utf-8"))
                    f_cur["status"] = new_status
                    f_cur["ai_review"] = {
                        "verdict": verdict,
                        "reasoning": reasoning,
                        "reviewed_at": datetime.datetime.now().isoformat(),
                        "tool": tool_name,
                    }
                    f_json.write_text(json.dumps(f_cur, indent=2), encoding="utf-8")
                except Exception:
                    pass

            timeline_p = f_dir / "timeline.json"
            if timeline_p.exists():
                try:
                    tdata = json.loads(timeline_p.read_text(encoding="utf-8"))
                    tdata.append({
                        "timestamp": datetime.datetime.now().isoformat(),
                        "event": "ai_review",
                        "verdict": verdict,
                        "reason": reasoning,
                        "source": f"ai_review ({tool_name})",
                    })
                    timeline_p.write_text(json.dumps(tdata, indent=2), encoding="utf-8")
                except Exception:
                    pass

            try:
                from nyx.core.evidence import add_evidence
                add_evidence(
                    finding_id=fid,
                    ev_type="ai_review",
                    content=json.dumps({"verdict": verdict, "reasoning": reasoning, "tool": tool_name}),
                    description=f"AI Validation Review Verdict: {verdict}",
                    source="ai_reviewer",
                    base_dir=base_dir,
                )
            except Exception:
                pass

            _sync_findings_index(d)

    return {
        "status": "success",
        "finding_id": fid,
        "verdict": verdict,
        "reasoning": reasoning,
        "new_status": new_status,
        "tool": tool_name,
    }


# Function aliases for backward compatibility and test suites
create = create_finding
list = list_findings
transition = transition_finding
triage = triage_finding
report = report_finding
review = review_finding_evidence
delete = delete_finding