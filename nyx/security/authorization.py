"""
NYX Security Domain Logic Engine
Authorization, Scope, Policies, and Canonical Evidence Sanitization
"""
from __future__ import annotations
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any
from nyx.infrastructure.filesystem import _get_eng_dir

SENSITIVE_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token",
    "x-session-token", "x-xsrf-token"
}

SENSITIVE_PARAM_NAMES = {
    "password", "passwd", "pass", "secret", "token", "access_token",
    "refresh_token", "id_token", "api_key", "apikey", "auth",
    "authorization", "session", "session_id", "sessionid", "cookie",
    "csrf", "xsrf", "private_key", "client_secret"
}


class SanitizationResult:
    def __init__(self, content: str | bytes, status: str, redactions_count: int):
        self.content = content
        self.status = status  # "sanitized", "not_required", "not_inspected", "failed"
        self.redactions_count = redactions_count
        self.redacted = (redactions_count > 0)

def check_authorization(target_domain: str | None = None, base_dir: Path | None = None) -> tuple[bool, str]:
    """Check .engagement/authorization.yaml and scope boundaries."""
    d = _get_eng_dir(create=False, base_dir=base_dir)
    auth_file = d / "authorization.yaml"
    if not auth_file.exists():
        return False, "Missing authorization.yaml in .engagement/ directory."

    try:
        content = auth_file.read_text(encoding="utf-8")
        if "authorized: true" not in content.lower():
            return False, "Authorization revoked or set to false in authorization.yaml."
    except Exception as e:
        return False, f"Could not read authorization.yaml: {e}"

    return True, "Authorized"


def get_engagement_scope(base_dir: Path | None = None) -> list[str]:
    """Retrieve list of in-scope host patterns from .engagement/target.yaml."""
    d = _get_eng_dir(create=False, base_dir=base_dir)
    t_file = d / "target.yaml"
    scopes = []
    if t_file.exists():
        try:
            for line in t_file.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("-") or "scope" in line:
                    val = line.split(":")[-1].replace("-", "").strip().strip('"').strip("'")
                    if val and val != "scope":
                        scopes.append(val.lower())
        except Exception:
            pass
    return scopes


def is_hostname_in_scope(hostname: str, scope_list: list[str] | None = None, base_dir: Path | None = None) -> bool:
    """Validate if target hostname falls within allowed engagement scope rules."""
    s_list = scope_list if scope_list is not None else get_engagement_scope(base_dir=base_dir)
    if not s_list:
        return True
    host = hostname.lower().strip().rstrip(".")
    for sc in s_list:
        sc_clean = sc.lower().strip().rstrip(".")
        if sc_clean.startswith("*."):
            domain_part = sc_clean[2:]
            if host == domain_part or host.endswith("." + domain_part):
                return True
        elif host == sc_clean or host.endswith("." + sc_clean):
            return True
    return False


def get_scope_status(hostname: str | None = None, base_dir: Path | None = None) -> dict[str, Any]:
    """Retrieve detailed scope status for a target domain or active workspace."""
    d = _get_eng_dir(create=False, base_dir=base_dir)
    t_file = d / "target.yaml"

    if not t_file.exists():
        return {
            "status": "UNCONFIGURED",
            "scope_state": "UNCONFIGURED",
            "in_scope": False,
            "allowed_mode": "DRY_RUN",
            "scope_list": [],
        }

    scope_list = get_engagement_scope(base_dir=base_dir)
    if not scope_list:
        return {
            "status": "UNCONFIGURED",
            "scope_state": "UNCONFIGURED",
            "in_scope": False,
            "allowed_mode": "DRY_RUN",
            "scope_list": [],
        }

    if hostname:
        in_scope = is_hostname_in_scope(hostname, scope_list=scope_list, base_dir=base_dir)
        if in_scope:
            return {
                "status": "CONFIGURED",
                "scope_state": "CONFIGURED",
                "in_scope": True,
                "allowed_mode": "LIVE",
                "scope_list": scope_list,
            }
        else:
            return {
                "status": "OUT_OF_SCOPE",
                "scope_state": "OUT_OF_SCOPE",
                "in_scope": False,
                "allowed_mode": "BLOCKED",
                "scope_list": scope_list,
            }

    return {
        "status": "CONFIGURED",
        "scope_state": "CONFIGURED",
        "in_scope": True,
        "allowed_mode": "LIVE",
        "scope_list": scope_list,
    }


def get_authorization_status(target_domain: str | None = None, base_dir: Path | None = None) -> dict[str, Any]:
    """Retrieve structured authorization status."""
    d = _get_eng_dir(create=False, base_dir=base_dir)
    auth_file = d / "authorization.yaml"
    if not auth_file.exists():
        return {
            "status": "PENDING",
            "authorized": False,
            "reason": "Missing authorization.yaml in .engagement/ directory.",
        }

    try:
        content = auth_file.read_text(encoding="utf-8")
        if "authorized: true" in content.lower():
            return {
                "status": "APPROVED",
                "authorized": True,
                "reason": "Authorized",
            }
        else:
            return {
                "status": "DENIED",
                "authorized": False,
                "reason": "Authorization revoked or set to false in authorization.yaml.",
            }
    except Exception as e:
        return {
            "status": "DENIED",
            "authorized": False,
            "reason": f"Could not read authorization.yaml: {e}",
        }

def _sanitize_text_content(val: str) -> tuple[str, int]:
    """Core regex-based text content sanitization pipeline."""
    if not isinstance(val, str) or not val:
        return val, 0

    count = 0
    text = val

    # 1. Basic Auth
    def _redact_basic(m: re.Match) -> str:
        nonlocal count
        prefix = m.group(1)
        cred = m.group(2)
        if cred != "[REDACTED]":
            count += 1
        return f"{prefix}[REDACTED]"

    text = re.sub(r'((?:Authorization|Proxy-Authorization):\s*Basic\s+)([^\s\r\n]+)', _redact_basic, text, flags=re.I)

    # 2. Bearer & Token Auth
    def _redact_bearer(m: re.Match) -> str:
        nonlocal count
        prefix = m.group(1)
        token = m.group(2)
        if token != "[REDACTED]":
            count += 1
        return f"{prefix}[REDACTED]"

    text = re.sub(r'((?:Authorization|Proxy-Authorization|X-Auth-Token|X-Access-Token|X-CSRF-Token|X-Session-Token)(?::\s*|\s+)(?:Bearer|Token)?\s*)([^\s\r\n]+)', _redact_bearer, text, flags=re.I)

    # 3. Cookie & Set-Cookie headers
    def _redact_cookie_header(m: re.Match) -> str:
        nonlocal count
        header_name = m.group(1)
        header_val = m.group(2)
        if header_val.strip() != "[REDACTED]":
            count += 1
        return f"{header_name}[REDACTED]"

    text = re.sub(r'((?:Set-Cookie|Cookie):\s*)([^\r\n]+)', _redact_cookie_header, text, flags=re.I)

    # 4. X-API-Key header
    def _redact_apikey_header(m: re.Match) -> str:
        nonlocal count
        header_name = m.group(1)
        header_val = m.group(2)
        if header_val.strip() != "[REDACTED]":
            count += 1
        return f"{header_name}[REDACTED]"

    text = re.sub(r'((?:X-API-Key|X-ApiKey|X-Secret):\s*)([^\r\n]+)', _redact_apikey_header, text, flags=re.I)

    # 5. Sensitive query/form parameters
    def _redact_query_param(m: re.Match) -> str:
        nonlocal count
        param_prefix = m.group(1)
        param_val = m.group(2)
        if param_val != "[REDACTED]":
            count += 1
        return f"{param_prefix}[REDACTED]"

    param_pattern = r'((?:^|[\s?&])(?:password|passwd|pass|secret|token|access_token|refresh_token|id_token|api_key|apikey|auth|authorization|session|session_id|sessionid|cookie|csrf|xsrf|private_key|client_secret)=)([^&\s\r\n"\']+)'
    text = re.sub(param_pattern, _redact_query_param, text, flags=re.I)

    # 6. JSON-style key-value pairs
    def _redact_json_str(m: re.Match) -> str:
        nonlocal count
        prefix = m.group(1)
        val = m.group(2)
        if val != "[REDACTED]":
            count += 1
        return f'{prefix}"[REDACTED]"'

    text = re.sub(r'("(?:password|passwd|pass|secret|token|access_token|refresh_token|id_token|api_key|apikey|auth|authorization|session|session_id|sessionid|cookie|csrf|xsrf|private_key|client_secret)"\s*:\s*")([^"]+)"', _redact_json_str, text, flags=re.I)

    def _redact_json_raw(m: re.Match) -> str:
        nonlocal count
        prefix = m.group(1)
        val = m.group(2)
        if val != "[REDACTED]" and val != '"[REDACTED]"':
            count += 1
        return f'{prefix}"[REDACTED]"'

    text = re.sub(r'("(?:password|passwd|pass|secret|token|access_token|refresh_token|id_token|api_key|apikey|auth|authorization|session|session_id|sessionid|cookie|csrf|xsrf|private_key|client_secret)"\s*:\s*)([^\s,\}\r\n]+)', _redact_json_raw, text, flags=re.I)

    return text, count


def sanitize_json_data(data: Any) -> tuple[Any, int]:
    """Recursively sanitize JSON data structures, redacting sensitive keys."""
    count = 0
    if isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            is_sensitive = (k_lower in SENSITIVE_PARAM_NAMES or
                            any(s in k_lower for s in ("password", "passwd", "secret", "access_token", "refresh_token", "id_token", "api_key", "client_secret", "private_key")))
            if is_sensitive:
                if v != "[REDACTED]":
                    count += 1
                new_dict[k] = "[REDACTED]"
            else:
                new_v, sub_count = sanitize_json_data(v)
                count += sub_count
                new_dict[k] = new_v
        return new_dict, count
    elif isinstance(data, list):
        new_list = []
        for item in data:
            new_item, sub_count = sanitize_json_data(item)
            count += sub_count
            new_list.append(new_item)
        return new_list, count
    elif isinstance(data, str):
        sanitized_str, str_count = _sanitize_text_content(data)
        return sanitized_str, str_count
    return data, 0


def sanitize_form_data(body_str: str) -> tuple[str, int]:
    """Sanitize form-urlencoded data string."""
    parts = body_str.split("&")
    new_parts = []
    count = 0
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            k_un = urllib.parse.unquote(k)
            k_lower = k_un.lower()
            is_sensitive = (k_lower in SENSITIVE_PARAM_NAMES or
                            any(s in k_lower for s in ("password", "passwd", "secret", "access_token", "refresh_token", "id_token", "api_key", "client_secret", "private_key")))
            if is_sensitive:
                if v != "[REDACTED]":
                    count += 1
                new_parts.append(f"{k}=[REDACTED]")
            else:
                v_san, c_san = _sanitize_text_content(v)
                count += c_san
                new_parts.append(f"{k}={v_san}")
        else:
            new_parts.append(part)
    return "&".join(new_parts), count


def sanitize_canonical_evidence(content: str | bytes, ev_type: str = "note") -> SanitizationResult:
    """Canonical Evidence Sanitization Engine for all evidence types."""
    if ev_type in ("screenshot", "attachment") and isinstance(content, bytes):
        return SanitizationResult(
            content=content,
            status="not_inspected",
            redactions_count=0
        )

    if not isinstance(content, str):
        if isinstance(content, bytes):
            try:
                content = content.decode("utf-8")
            except Exception:
                return SanitizationResult(
                    content=content,
                    status="not_inspected",
                    redactions_count=0
                )
        else:
            return SanitizationResult(
                content=str(content),
                status="not_required",
                redactions_count=0
            )

    try:
        total_redactions = 0
        working_content = content

        # Check if content is JSON
        trimmed = working_content.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                parsed_json = json.loads(trimmed)
                sanitized_json, json_redactions = sanitize_json_data(parsed_json)
                working_content = json.dumps(sanitized_json, indent=2)
                total_redactions += json_redactions
            except Exception:
                pass

        # Check if content is form-urlencoded
        if "password=" in working_content.lower() or "token=" in working_content.lower() or "secret=" in working_content.lower():
            if not working_content.startswith("GET ") and not working_content.startswith("POST "):
                if "=" in working_content and ("&" in working_content or working_content.count("=") == 1):
                    try:
                        working_content, form_redactions = sanitize_form_data(working_content)
                        total_redactions += form_redactions
                    except Exception:
                        pass

        # Apply canonical regex text sanitization across headers/URLs/strings
        final_content, text_redactions = _sanitize_text_content(working_content)
        total_redactions += text_redactions

        return SanitizationResult(
            content=final_content,
            status="sanitized",
            redactions_count=total_redactions
        )
    except Exception:
        # FAIL-SAFE: If sanitization throws an error, return status='failed'
        return SanitizationResult(
            content="",
            status="failed",
            redactions_count=0
        )


def _sanitize_sensitive(val: str) -> str:
    """Wrapper using the canonical sanitization engine."""
    if not isinstance(val, str):
        return val
    res = sanitize_canonical_evidence(val)
    return res.content if res.status != "failed" else val


def sanitize_evidence(content: str | bytes, ev_type: str = "note") -> tuple[str | bytes, bool, str, int]:
    """Canonical sanitization hook for security evidence before storage."""
    res = sanitize_canonical_evidence(content, ev_type=ev_type)
    return res.content, res.redacted, res.status, res.redactions_count