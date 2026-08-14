"""
NYX Execution Safety & Scope Policy Layer
"""
from __future__ import annotations
import re
from urllib.parse import urlparse
from nyx.security.authorization import check_authorization, get_engagement_scope, is_hostname_in_scope
from nyx.infrastructure.filesystem import _get_eng_dir


EXECUTION_CLASSES = ["PASSIVE", "SAFE_ACTIVE", "ACTIVE"]


def extract_hostname(target_str: str) -> str:
    if not target_str:
        return ""
    if "://" in target_str:
        try:
            return urlparse(target_str).hostname or target_str
        except Exception:
            pass
    # Strip path or query
    clean = target_str.split("/")[0].split(":")[0].split("?")[0]
    return clean.strip().lower()


def is_strict_scope_match(hostname: str, scope_list: list[str]) -> bool:
    clean_host = extract_hostname(hostname)
    if not clean_host:
        return False
    return is_hostname_in_scope(clean_host, scope_list)


def check_policy(
    tool_name: str,
    target: str,
    execution_class: str = "SAFE_ACTIVE",
    active_permitted: bool = False,
    dry_run: bool = False,
) -> tuple[bool, str, str]:
    """Verify command execution safety:
    1. Scope verification
    2. Authorization state check
    3. Execution class permission enforcement
    Returns (allowed, status_msg, scope_status)."""

    clean_target = extract_hostname(target)
    scope_list = get_engagement_scope()

    # Scope check
    if scope_list and clean_target:
        if not is_strict_scope_match(clean_target, scope_list):
            return False, "Target outside authorized engagement scope", "OUT_OF_SCOPE"
        scope_status = "CONFIGURED"
    else:
        # If no scope configured yet
        scope_status = "UNCONFIGURED"
        if not dry_run:
            return False, "Target scope is not configured", "UNCONFIGURED"

    # Authorization check
    auth_ok, auth_msg = check_authorization(clean_target)
    if not auth_ok and execution_class != "PASSIVE" and not dry_run:
        return False, f"Authorization Check Failed: {auth_msg}", "UNAUTHORIZED"

    # Execution class policy
    exec_cls = execution_class.upper()
    if exec_cls not in EXECUTION_CLASSES:
        exec_cls = "SAFE_ACTIVE"

    if exec_cls == "ACTIVE" and not active_permitted and not dry_run:
        d = _get_eng_dir()
        allow_active = False
        if d.exists():
            auth_yaml = d / "authorization.yaml"
            if auth_yaml.exists():
                txt = auth_yaml.read_text(encoding="utf-8").lower()
                if "allow_active: true" in txt or "active: true" in txt or "active_testing: true" in txt:
                    allow_active = True
        if not allow_active:
            return False, "ACTIVE execution class blocked by safety policy (requires explicit active authorization).", scope_status

    return True, "Execution policy satisfied", scope_status
