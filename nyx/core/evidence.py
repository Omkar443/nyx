"""
NYX Core Evidence Storage & Sanitization Module
Canonical business logic for evidence vault management, hashing, sanitization, and verification.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

from nyx.infrastructure.filesystem import REPO_ROOT, _get_eng_dir, calculate_file_hash
from nyx.security.authorization import (
    sanitize_canonical_evidence,
    _sanitize_text_content,
)


def _get_evidence_dir(
    finding_id: str, create: bool = True, base_dir: Path | None = None
) -> tuple[Path | None, str]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return None, "No active engagement workspace found (.engagement/)."

    findings_file = d / "findings.json"
    findings = []
    if findings_file.exists():
        try:
            findings = json.loads(findings_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    known_fids = {f.get("finding_id") for f in findings if f.get("finding_id")}
    ev_base = d / "evidence" / finding_id

    if not create and finding_id not in known_fids and not ev_base.exists():
        return None, f"Finding '{finding_id}' does not exist in current engagement."

    if create:
        ev_base.mkdir(parents=True, exist_ok=True)
        (ev_base / "requests").mkdir(exist_ok=True)
        (ev_base / "responses").mkdir(exist_ok=True)
        (ev_base / "attachments").mkdir(exist_ok=True)
        notes_file = ev_base / "notes.md"
        if not notes_file.exists():
            notes_file.write_text(f"# Evidence Notes — {finding_id}\n\n", encoding="utf-8")
        meta_file = ev_base / "metadata.json"
        if not meta_file.exists():
            meta_file.write_text("[]", encoding="utf-8")

    return ev_base, "OK"


def _generate_evidence_id(eng_dir: Path, year: int | None = None) -> str:
    if year is None:
        year = datetime.datetime.now().year
    ev_root = eng_dir / "evidence"
    max_seq = 0
    if ev_root.exists():
        for meta_p in ev_root.glob("*/metadata.json"):
            try:
                items = json.loads(meta_p.read_text(encoding="utf-8"))
                for item in items:
                    eid = item.get("evidence_id", "")
                    if eid.startswith(f"EV-{year}-"):
                        seq_str = eid.split("-")[-1]
                        if seq_str.isdigit():
                            max_seq = max(max_seq, int(seq_str))
            except Exception:
                pass
    return f"EV-{year}-{max_seq + 1:04d}"


def add_evidence(
    finding_id: str,
    ev_type: str = "note",
    content: str | None = None,
    file: str | Path | None = None,
    description: str = "",
    source: str = "manual",
    base_dir: Path | None = None,
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {"status": "error", "message": "No active engagement workspace found."}

    ev_dir, err_msg = _get_evidence_dir(finding_id, create=True, base_dir=base_dir)
    if not ev_dir:
        return {"status": "error", "message": err_msg}

    etype = ev_type or "note"
    desc = description or f"{etype} for {finding_id}"
    raw_content = ""

    if file:
        src_file = Path(file)
        if not src_file.exists():
            return {"status": "error", "message": f"Source file not found: {src_file}"}
        raw_content = src_file.read_text(encoding="utf-8", errors="replace")
    elif content is not None:
        raw_content = content
    else:
        return {"status": "error", "message": "Must provide either --content or --file for evidence."}

    san_res = sanitize_canonical_evidence(raw_content, ev_type=etype)
    if san_res.status == "failed":
        return {"status": "error", "message": "Evidence sanitization failed. Raw evidence was not persisted."}

    sanitized_content = san_res.content
    is_redacted = san_res.redacted
    san_status = san_res.status
    redactions_cnt = san_res.redactions_count

    eid = _generate_evidence_id(d)
    type_folder = (
        "requests"
        if etype == "http_request"
        else (
            "responses"
            if etype == "http_response"
            else ("attachments" if etype in ("screenshot", "attachment") else "notes")
        )
    )

    if etype == "note":
        rel_file = "notes.md"
        target_file = ev_dir / rel_file
        existing_text = (
            target_file.read_text(encoding="utf-8")
            if target_file.exists()
            else f"# Evidence Notes — {finding_id}\n\n"
        )
        existing_text += f"## [{eid}] {desc}\n_{datetime.datetime.now().isoformat()}_\n\n```\n{sanitized_content}\n```\n\n"
        target_file.write_text(existing_text, encoding="utf-8")
    elif etype in ("screenshot", "attachment") and isinstance(raw_content, bytes):
        ext = ".bin"
        rel_file = f"{type_folder}/{eid}{ext}"
        target_file = ev_dir / rel_file
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_bytes(raw_content)
    else:
        ext = ".txt" if etype in ("http_request", "http_response") else ".bin"
        rel_file = f"{type_folder}/{eid}{ext}"
        target_file = ev_dir / rel_file
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(str(sanitized_content), encoding="utf-8")

    sha256 = calculate_file_hash(target_file)

    meta_file = ev_dir / "metadata.json"
    meta_items = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.exists() else []
    item_data = {
        "evidence_id": eid,
        "finding_id": finding_id,
        "type": etype,
        "source": source,
        "created_at": datetime.datetime.now().isoformat(),
        "description": desc,
        "file": rel_file,
        "sha256": sha256,
        "redacted": is_redacted,
        "sanitization_status": san_status,
        "redactions_count": redactions_cnt,
    }
    meta_items.append(item_data)

    temp_meta = meta_file.with_suffix(".json.tmp")
    temp_meta.write_text(json.dumps(meta_items, indent=2), encoding="utf-8")
    temp_meta.replace(meta_file)

    return {
        "status": "success",
        "evidence_id": eid,
        "finding_id": finding_id,
        "type": etype,
        "file": rel_file,
        "sha256": sha256,
        "sanitization_status": san_status,
        "redactions_count": redactions_cnt,
        "item": item_data,
    }


def list_evidence(
    finding_id: str, base_dir: Path | None = None
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {"status": "error", "message": "No active engagement workspace found."}

    ev_dir = d / "evidence" / finding_id
    meta_file = ev_dir / "metadata.json"

    findings_file = d / "findings.json"
    known_fids = set()
    if findings_file.exists():
        try:
            known_fids = {
                f.get("finding_id")
                for f in json.loads(findings_file.read_text(encoding="utf-8"))
                if f.get("finding_id")
            }
        except Exception:
            pass

    if finding_id not in known_fids and not ev_dir.exists():
        return {"status": "error", "message": f"Finding '{finding_id}' does not exist in current engagement."}

    if not meta_file.exists():
        return {"status": "success", "finding_id": finding_id, "evidence": []}

    items = json.loads(meta_file.read_text(encoding="utf-8"))
    for item in items:
        target_file = ev_dir / item.get("file", "")
        current_hash = calculate_file_hash(target_file)
        expected_hash = item.get("sha256", "")
        item["integrity"] = "PASS" if (current_hash and current_hash == expected_hash) else "FAIL"

    return {"status": "success", "finding_id": finding_id, "evidence": items}


def show_evidence(
    evidence_id: str, base_dir: Path | None = None
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {"status": "error", "message": "No active engagement workspace found."}

    ev_root = d / "evidence"
    found_item = None
    found_ev_dir = None

    if ev_root.exists():
        for meta_p in ev_root.glob("*/metadata.json"):
            try:
                items = json.loads(meta_p.read_text(encoding="utf-8"))
                for item in items:
                    if item.get("evidence_id") == evidence_id:
                        found_item = item
                        found_ev_dir = meta_p.parent
                        break
            except Exception:
                pass
            if found_item:
                break

    if not found_item or not found_ev_dir:
        return {"status": "error", "message": f"Evidence ID '{evidence_id}' not found in engagement workspace."}

    target_file = found_ev_dir / found_item.get("file", "")
    preview_lines = []
    if target_file.exists() and target_file.suffix in (".txt", ".md", ".json", ""):
        content = target_file.read_text(encoding="utf-8", errors="replace")
        san_res = _sanitize_text_content(content)
        san_preview = san_res[0] if isinstance(san_res, tuple) else san_res
        preview_lines = str(san_preview).splitlines()[:20]

    return {
        "status": "success",
        "evidence": found_item,
        "ev_dir": str(found_ev_dir),
        "preview_lines": preview_lines,
    }


def verify_evidence(
    evidence_id: str, base_dir: Path | None = None
) -> dict[str, Any]:
    res = show_evidence(evidence_id, base_dir=base_dir)
    if res.get("status") == "error":
        return res

    item = res.get("evidence", {})
    ev_dir = Path(res.get("ev_dir", ""))
    target_file = ev_dir / item.get("file", "")
    expected_hash = item.get("sha256", "")
    current_hash = calculate_file_hash(target_file)

    passed = bool(current_hash and current_hash == expected_hash)
    return {
        "status": "success",
        "evidence_id": evidence_id,
        "integrity": "PASS" if passed else "FAIL",
        "expected_hash": expected_hash,
        "current_hash": current_hash,
    }
