"""
NYX Core Engagement & Workspace Module
Canonical business logic for engagement workspace lifecycle, workflow state machine, and persistent memory.
"""
from __future__ import annotations

import datetime
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from nyx.infrastructure.filesystem import (
    ENGAGEMENT_DIR_NAME,
    VALID_STATES,
    _get_eng_dir,
)
from nyx.infrastructure.urls import normalize_url
from nyx.security.authorization import (
    check_authorization,
    get_engagement_scope,
    is_hostname_in_scope,
    _sanitize_text_content,
)


def init_engagement(
    target: str,
    reset: bool = False,
    force: bool = False,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    target_name = target or "example.com"
    d = _get_eng_dir(create=True, base_dir=base_dir)
    target_yaml = d / "target.yaml"

    do_reset = reset or force
    existing_target = None

    if target_yaml.exists():
        try:
            existing_text = target_yaml.read_text(encoding="utf-8")
            for line in existing_text.splitlines():
                line_s = line.strip()
                if (
                    line_s.startswith("domain:")
                    or line_s.startswith("name:")
                    or line_s.startswith("target:")
                ):
                    val = line_s.split(":", 1)[1].strip().strip('"').strip("'")
                    if val:
                        existing_target = val
                        break

            if existing_target and existing_target.lower() != target_name.lower() and not do_reset:
                return {
                    "status": "error",
                    "code": "EXISTS",
                    "existing_target": existing_target,
                    "target": target_name,
                    "message": f"Existing engagement workspace found for target '{existing_target}'. Cannot re-initialize for '{target_name}' without explicit reset/force flag.",
                }
        except Exception:
            pass

    if do_reset and d.exists():
        for child in list(d.iterdir()):
            try:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            except Exception:
                pass
        target_yaml = d / "target.yaml"

    if not target_yaml.exists():
        from nyx.execution.policy import extract_hostname
        import re
        clean_host = extract_hostname(target_name)
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_host)) or clean_host in ("localhost", "127.0.0.1")
        if is_ip:
            scope_lines = f'    - "{clean_host}"\n    - "{target_name}"'
        else:
            scope_lines = f'    - "*.{clean_host}"\n    - "{clean_host}"\n    - "{target_name}"'

        target_yaml.write_text(
            f"""target:
  name: {target_name}
  domain: {target_name}
  authorization: confirmed
  scope:
{scope_lines}
  exclusions:
    - "out-of-scope.{clean_host}"
  start_date: "{datetime.date.today().isoformat()}"
""",
            encoding="utf-8",
        )

    auth_yaml = d / "authorization.yaml"
    if not auth_yaml.exists():
        auth_yaml.write_text(
            f"""authorized: true
target:
  - {target_name}
allowed:
  - web
  - api
excluded:
  - third-party
  - production-user-data
""",
            encoding="utf-8",
        )

    state_json = d / "state.json"
    if not state_json.exists():
        state_json.write_text(
            json.dumps(
                {
                    "state": "DISCOVERY",
                    "mode": "RESEARCH",
                    "completed": ["engagement_init"],
                    "history": [],
                    "updated_at": datetime.datetime.now().isoformat(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    for f_name, default_val in [
        (
            "technologies.json",
            {
                "frameworks": [],
                "servers": [],
                "APIs": [],
                "authentication": [],
                "cloud": [],
                "databases": [],
            },
        ),
        ("endpoints.json", []),
        ("tested_vectors.json", []),
        ("findings.json", []),
    ]:
        p = d / f_name
        if not p.exists():
            p.write_text(json.dumps(default_val, indent=2), encoding="utf-8")

    notes_md = d / "notes.md"
    if not notes_md.exists():
        notes_md.write_text(
            f"# Engagement Notes — {target_name}\n\nInitiated on {datetime.date.today().isoformat()}\n",
            encoding="utf-8",
        )

    return {
        "status": "success",
        "dir": str(d),
        "target": target_name,
        "reset_performed": bool(existing_target and do_reset),
        "files": [
            "target.yaml",
            "authorization.yaml",
            "state.json",
            "technologies.json",
            "endpoints.json",
            "tested_vectors.json",
            "findings.json",
            "notes.md",
        ],
    }


def get_engagement_target(base_dir: Path | None = None) -> str | None:
    """Retrieve the authoritative active engagement target domain/URL from .engagement/target.yaml."""
    d = _get_eng_dir(create=False, base_dir=base_dir)
    target_yaml = d / "target.yaml"
    if target_yaml.exists():
        try:
            for line in target_yaml.read_text(encoding="utf-8").splitlines():
                line_s = line.strip()
                if line_s.startswith("domain:") or line_s.startswith("name:") or line_s.startswith("target:"):
                    val = line_s.split(":", 1)[1].strip().strip('"').strip("'")
                    if val and val not in ("target", "scope", "exclusions"):
                        return val
        except Exception:
            pass
    return None


def get_engagement_status(base_dir: Path | None = None) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {
            "status": "error",
            "message": "No active engagement workspace found in current directory.",
        }

    target_name = get_engagement_target(base_dir=base_dir) or "No active target"
    state_file = d / "state.json"
    state_data = (
        json.loads(state_file.read_text(encoding="utf-8"))
        if state_file.exists()
        else {}
    )
    state = state_data.get("state", "UNINITIALIZED")
    mode = state_data.get("mode", "RESEARCH")

    counts = {}
    for fname in ["endpoints.json", "tested_vectors.json", "findings.json"]:
        p = d / fname
        cnt = len(json.loads(p.read_text(encoding="utf-8"))) if p.exists() else 0
        counts[fname.replace(".json", "")] = cnt

    return {
        "status": "success",
        "dir": str(d),
        "target": target_name,
        "state": state,
        "mode": mode,
        "counts": counts,
        "completed": state_data.get("completed", []),
        "updated_at": state_data.get("updated_at", "N/A"),
    }


def export_engagement(
    base_dir: Path | None = None, out_path: Path | None = None
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {
            "status": "error",
            "message": "No active engagement workspace found.",
        }

    target_out = (
        out_path
        or Path.cwd()
        / f"engagement_export_{datetime.date.today().isoformat()}.json"
    )
    export_data = {}
    for fname in [
        "state.json",
        "technologies.json",
        "endpoints.json",
        "tested_vectors.json",
        "findings.json",
    ]:
        p = d / fname
        if p.exists():
            export_data[fname.replace(".json", "")] = json.loads(
                p.read_text(encoding="utf-8")
            )

    target_out.write_text(json.dumps(export_data, indent=2), encoding="utf-8")
    return {
        "status": "success",
        "export_file": str(target_out),
        "keys": list(export_data.keys()),
    }


def set_engagement_state(
    new_state: str | None = None,
    mode: str | None = None,
    force_state: bool = False,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {
            "status": "error",
            "message": "No active engagement workspace found.",
        }

    state_file = d / "state.json"
    state_data = (
        json.loads(state_file.read_text(encoding="utf-8"))
        if state_file.exists()
        else {
            "state": "DISCOVERY",
            "completed": [],
            "history": [],
            "mode": "RESEARCH",
        }
    )

    mode_changed = False
    if mode:
        new_mode = mode.upper()
        if new_mode in ("RESEARCH", "STRICT"):
            state_data["mode"] = new_mode
            state_data["updated_at"] = datetime.datetime.now().isoformat()
            state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")
            mode_changed = True

    curr_state = state_data.get("state", "DISCOVERY")
    curr_mode = state_data.get("mode", "RESEARCH")

    if not new_state:
        return {
            "status": "success",
            "action": "query" if not mode_changed else "mode_set",
            "curr_state": curr_state,
            "curr_mode": curr_mode,
            "completed": state_data.get("completed", []),
            "updated_at": state_data.get("updated_at", "N/A"),
        }

    ns = new_state.upper()
    if ns not in VALID_STATES:
        return {
            "status": "error",
            "message": f"Invalid state transition: '{ns}'. Valid workflow states: {', '.join(VALID_STATES)}",
        }

    curr_idx = VALID_STATES.index(curr_state) if curr_state in VALID_STATES else 0
    new_idx = VALID_STATES.index(ns)

    valid_jump = False
    if curr_mode == "RESEARCH":
        if (
            (curr_state == "DISCOVERY" and ns in ("DISCOVERY", "ANALYSIS"))
            or (
                curr_state == "ANALYSIS"
                and ns in ("DISCOVERY", "ANALYSIS", "VALIDATION")
            )
            or (
                curr_state == "VALIDATION"
                and ns in ("ANALYSIS", "VALIDATION", "REPORTING")
            )
            or (curr_state == "REPORTING" and ns in ("VALIDATION", "REPORTING"))
        ):
            valid_jump = True
    else:
        if new_idx == curr_idx + 1 or new_idx == curr_idx:
            valid_jump = True

    if not valid_jump and not force_state:
        return {
            "status": "error",
            "code": "INVALID_TRANSITION",
            "curr_state": curr_state,
            "requested_state": ns,
            "curr_mode": curr_mode,
            "message": f"Invalid state transition sequence ({curr_state} -> {ns}) in {curr_mode} mode.",
        }

    history = state_data.setdefault("history", [])
    history.append(
        {
            "previous_state": curr_state,
            "new_state": ns,
            "timestamp": datetime.datetime.now().isoformat(),
            "reason": "Administrative override"
            if force_state
            else f"Workflow state change ({curr_mode} mode)",
        }
    )

    state_data["state"] = ns
    state_data["mode"] = curr_mode
    if curr_state not in state_data.get("completed", []):
        state_data.setdefault("completed", []).append(curr_state)
    state_data["updated_at"] = datetime.datetime.now().isoformat()
    state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")

    return {
        "status": "success",
        "old_state": curr_state,
        "new_state": ns,
        "mode": curr_mode,
        "force_applied": force_state,
    }


def add_memory(
    type_: str | None = None,
    value: str | None = None,
    priority: str = "P2",
    category: str = "frameworks",
    endpoint: str = "N/A",
    result: str = "tested",
    base_dir: Path | None = None,
    mem_type: str | None = None,
    val: str | None = None,
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {
            "status": "error",
            "message": "No active engagement workspace found.",
        }

    raw_val = value if value is not None else (val or "")
    val, _ = _sanitize_text_content(raw_val)
    mem_type = (type_ or mem_type or "note").lower()

    if mem_type == "endpoint":
        val = normalize_url(val)
        ep_file = d / "endpoints.json"
        endpoints = (
            json.loads(ep_file.read_text(encoding="utf-8"))
            if ep_file.exists()
            else []
        )
        endpoints.append(
            {
                "url": val,
                "priority": priority,
                "added_at": datetime.datetime.now().isoformat(),
            }
        )
        ep_file.write_text(json.dumps(endpoints, indent=2), encoding="utf-8")
        return {
            "status": "success",
            "type": "endpoint",
            "value": val,
            "priority": priority,
        }
    elif mem_type == "technology":
        tech_file = d / "technologies.json"
        techs = (
            json.loads(tech_file.read_text(encoding="utf-8"))
            if tech_file.exists()
            else {"frameworks": []}
        )
        if category not in techs:
            techs[category] = []
        if val not in techs[category]:
            techs[category].append(val)
        tech_file.write_text(json.dumps(techs, indent=2), encoding="utf-8")
        return {
            "status": "success",
            "type": "technology",
            "category": category,
            "value": val,
        }
    elif mem_type == "vector":
        v_file = d / "tested_vectors.json"
        vectors = (
            json.loads(v_file.read_text(encoding="utf-8")) if v_file.exists() else []
        )
        vectors.append(
            {
                "vector": val,
                "endpoint": endpoint,
                "result": result,
                "timestamp": datetime.datetime.now().isoformat(),
            }
        )
        v_file.write_text(json.dumps(vectors, indent=2), encoding="utf-8")
        return {"status": "success", "type": "vector", "value": val}
    else:
        notes_file = d / "notes.md"
        notes = (
            notes_file.read_text(encoding="utf-8") if notes_file.exists() else ""
        )
        notes += f"\n- [{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}] [{mem_type}] {val}\n"
        notes_file.write_text(notes, encoding="utf-8")
        return {"status": "success", "type": "note", "value": val}


def search_memory(
    query: str, base_dir: Path | None = None
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        return {
            "status": "error",
            "message": "No active engagement workspace found.",
        }

    q = query.lower()
    matches: list[dict[str, Any]] = []
    for fname in [
        "endpoints.json",
        "technologies.json",
        "tested_vectors.json",
        "findings.json",
        "notes.md",
    ]:
        p = d / fname
        if p.exists():
            text = p.read_text(encoding="utf-8")
            if q in text.lower():
                file_matches = [
                    line.strip()
                    for line in text.splitlines()
                    if q in line.lower()
                ]
                matches.append({"file": fname, "matches": file_matches})

    return {"status": "success", "query": query, "results": matches}


def import_burp_xml(
    xml_file: Path | str,
    include_out_of_scope: bool = False,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    d = _get_eng_dir(create=False, base_dir=base_dir)
    if not d.exists():
        raise RuntimeError("No active engagement workspace found.")

    p_file = Path(xml_file)
    if not p_file.exists():
        raise FileNotFoundError(f"Burp XML export file not found: {p_file}")

    tree = ET.parse(p_file)
    root = tree.getroot()

    auth_ok, auth_msg = check_authorization()
    if not auth_ok:
        raise PermissionError(f"Authorization requirement failed: {auth_msg}")

    scope = get_engagement_scope()

    parsed_count = 0
    in_scope_count = 0
    out_of_scope_count = 0
    new_count = 0
    existing_count = 0
    redacted_count = 0

    ep_file = d / "endpoints.json"
    endpoints = (
        json.loads(ep_file.read_text(encoding="utf-8")) if ep_file.exists() else []
    )
    existing_urls = {
        item["url"]
        for item in endpoints
        if isinstance(item, dict) and "url" in item
    }

    for item in root.findall("item"):
        parsed_count += 1
        url_el = item.find("url")
        host_el = item.find("host")

        raw_url = url_el.text.strip() if url_el is not None and url_el.text else ""
        raw_host = host_el.text.strip() if host_el is not None and host_el.text else ""

        if not raw_url:
            continue

        san_url, red_cnt = _sanitize_text_content(raw_url)
        if red_cnt > 0:
            redacted_count += red_cnt
        in_scope = is_hostname_in_scope(raw_host, scope) if raw_host else True

        if in_scope:
            in_scope_count += 1
        else:
            out_of_scope_count += 1
            if not include_out_of_scope:
                continue

        norm_url = normalize_url(san_url)
        if norm_url in existing_urls:
            existing_count += 1
        else:
            existing_urls.add(norm_url)
            endpoints.append(
                {
                    "url": norm_url,
                    "source": "burp_xml",
                    "in_scope": in_scope,
                    "added_at": datetime.datetime.now().isoformat(),
                }
            )
            new_count += 1

    ep_file.write_text(json.dumps(endpoints, indent=2), encoding="utf-8")

    return {
        "parsed": parsed_count,
        "in_scope": in_scope_count,
        "out_of_scope": out_of_scope_count,
        "new": new_count,
        "existing": existing_count,
        "redacted": redacted_count,
    }


# Function aliases for backward compatibility and test suites
init = init_engagement
set_state = set_engagement_state
get_status = get_engagement_status
export = export_engagement
add = add_memory
record_memory = add_memory