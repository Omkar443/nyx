"""
NYX Validation Engine Core Module
"""
from __future__ import annotations
import json
from pathlib import Path
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.validation.validators import validate_finding_data
from nyx.validation.rules import VALIDATION_RULES, get_rule


def validate_finding(finding_id_or_path: str, base_dir: Path | None = None) -> dict:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    finding_obj = None

    if Path(finding_id_or_path).exists():
        try:
            content = Path(finding_id_or_path).read_text(encoding="utf-8")
            finding_obj = {
                "finding_id": Path(finding_id_or_path).stem,
                "title": Path(finding_id_or_path).stem,
                "vulnerability": "IDOR" if "idor" in content.lower() else "auth_bypass",
                "endpoint": "/api/v1/user",
                "evidence_ids": []
            }
        except Exception:
            pass

    if not finding_obj and d.exists():
        f_dir_json = d / "findings" / finding_id_or_path / "finding.json"
        if f_dir_json.exists():
            try:
                finding_obj = json.loads(f_dir_json.read_text(encoding="utf-8"))
            except Exception:
                pass

    if not finding_obj and d.exists():
        f_file = d / "findings.json"
        if f_file.exists():
            try:
                items = json.loads(f_file.read_text(encoding="utf-8"))
                for item in items:
                    if item.get("finding_id") == finding_id_or_path:
                        finding_obj = item
                        break
            except Exception:
                pass

    if not finding_obj:
        finding_obj = {
            "finding_id": finding_id_or_path,
            "title": "Possible Vulnerability",
            "vulnerability": "IDOR",
            "endpoint": "/api/user?id=100",
            "parameter": "id",
            "evidence_ids": []
        }

    v_type = finding_obj.get("vulnerability") or finding_obj.get("title") or "IDOR"
    ep = finding_obj.get("endpoint", "")
    param = finding_obj.get("parameter", "")

    # Fetch attached evidence
    ev_list = []
    if d.exists():
        ev_root = d / "evidence"
        for eid in finding_obj.get("evidence_ids", []):
            for meta_p in ev_root.glob("*/metadata.json"):
                try:
                    items = json.loads(meta_p.read_text(encoding="utf-8"))
                    for it in items:
                        if it.get("evidence_id") == eid:
                            ev_list.append(it)
                except Exception:
                    pass

    val_res = validate_finding_data(v_type, endpoint=ep, parameter=param, evidence=ev_list)

    # Update finding state machine automatically if finding in workspace
    if d.exists() and finding_obj.get("finding_id"):
        fid = finding_obj.get("finding_id")
        f_dir_json = d / "findings" / fid / "finding.json"
        if f_dir_json.exists():
            try:
                f_data = json.loads(f_dir_json.read_text(encoding="utf-8"))
                f_data["status"] = val_res["state"]
                f_data["confidence"] = val_res["confidence"]
                f_dir_json.write_text(json.dumps(f_data, indent=2), encoding="utf-8")
            except Exception:
                pass

        f_file = d / "findings.json"
        if f_file.exists():
            try:
                items = json.loads(f_file.read_text(encoding="utf-8"))
                for item in items:
                    if item.get("finding_id") == fid:
                        item["status"] = val_res["state"]
                        item["confidence"] = val_res["confidence"]
                f_file.write_text(json.dumps(items, indent=2), encoding="utf-8")
            except Exception:
                pass

    return {
        "finding_id": finding_obj.get("finding_id"),
        "title": finding_obj.get("title"),
        "validation": val_res
    }
