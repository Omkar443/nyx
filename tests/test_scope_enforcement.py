"""
NYX Scope Configuration Enforcement & Dashboard Status Regression Tests
"""
import os
import shutil
import tempfile
from pathlib import Path
import pytest

from nyx.security.authorization import get_scope_status, get_authorization_status
from nyx.execution.policy import check_policy
from nyx.execution.engine import ExecutionEngine
from nyx.models.execution import ExecutionStatus


@pytest.fixture
def temp_eng_dir():
    tmp_dir = Path(tempfile.mkdtemp(prefix="nyx_scope_test_"))
    eng_dir = tmp_dir / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    orig_cwd = os.getcwd()
    os.chdir(tmp_dir)
    yield tmp_dir
    os.chdir(orig_cwd)
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_configured_scope_allows_execution(temp_eng_dir):
    """Test 1: Configured scope allows execution."""
    eng_dir = temp_eng_dir / ".engagement"
    (eng_dir / "target.yaml").write_text("target: example.com\nscope:\n  - example.com\n  - *.example.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    scope_info = get_scope_status("example.com", base_dir=temp_eng_dir)
    assert scope_info["status"] == "CONFIGURED"
    assert scope_info["in_scope"] is True
    assert scope_info["allowed_mode"] == "LIVE"

    policy_ok, msg, scope_status = check_policy("subfinder", "example.com", dry_run=False)
    assert policy_ok is True
    assert scope_status == "CONFIGURED"


def test_unconfigured_scope_allows_dry_run(temp_eng_dir):
    """Test 2: Unconfigured scope allows passive dry-run."""
    eng_dir = temp_eng_dir / ".engagement"
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    scope_info = get_scope_status("example.com", base_dir=temp_eng_dir)
    assert scope_info["status"] == "UNCONFIGURED"
    assert scope_info["allowed_mode"] == "DRY_RUN"

    policy_ok, msg, scope_status = check_policy("subfinder", "example.com", dry_run=True)
    assert policy_ok is True
    assert scope_status == "UNCONFIGURED"

    engine = ExecutionEngine(base_dir=temp_eng_dir)
    res = engine.execute("subfinder", "example.com", dry_run=True)
    assert res.status == ExecutionStatus.COMPLETED.value
    assert res.dry_run is True
    assert res.scope_status == "UNCONFIGURED"


def test_unconfigured_scope_blocks_active_scan(temp_eng_dir):
    """Test 3: Unconfigured scope blocks active live execution."""
    eng_dir = temp_eng_dir / ".engagement"
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    policy_ok, msg, scope_status = check_policy("subfinder", "example.com", dry_run=False)
    assert policy_ok is False
    assert "Target scope is not configured" in msg
    assert scope_status == "UNCONFIGURED"

    engine = ExecutionEngine(base_dir=temp_eng_dir)
    res = engine.execute("subfinder", "example.com", dry_run=False)
    assert res.status == ExecutionStatus.BLOCKED.value
    assert "Target scope is not configured" in (res.error_message or res.stderr)


def test_out_of_scope_target_blocked(temp_eng_dir):
    """Test 4: Out-of-scope target is blocked."""
    eng_dir = temp_eng_dir / ".engagement"
    (eng_dir / "target.yaml").write_text("target: example.com\nscope:\n  - example.com\n", encoding="utf-8")
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    scope_info = get_scope_status("unauthorized-domain.com", base_dir=temp_eng_dir)
    assert scope_info["status"] == "OUT_OF_SCOPE"
    assert scope_info["in_scope"] is False

    policy_ok, msg, scope_status = check_policy("subfinder", "unauthorized-domain.com", dry_run=False)
    assert policy_ok is False
    assert "Target outside authorized engagement scope" in msg
    assert scope_status == "OUT_OF_SCOPE"

    engine = ExecutionEngine(base_dir=temp_eng_dir)
    res = engine.execute("subfinder", "unauthorized-domain.com", dry_run=False)
    assert res.status == ExecutionStatus.BLOCKED.value
    assert res.scope_status == "OUT_OF_SCOPE"


def test_dashboard_api_structured_scope_data(temp_eng_dir):
    """Test 5: Structured scope and authorization data in ExecutionResult dictionary."""
    eng_dir = temp_eng_dir / ".engagement"
    (eng_dir / "authorization.yaml").write_text("authorized: true\n", encoding="utf-8")

    engine = ExecutionEngine(base_dir=temp_eng_dir)
    res = engine.execute("subfinder", "example.com", dry_run=True)
    d = res.to_dict()

    assert "scope" in d
    assert d["scope"]["status"] == "UNCONFIGURED"
    assert d["scope"]["allowed_mode"] == "DRY_RUN"
    assert "authorization" in d
    assert d["authorization"]["status"] == "APPROVED"


def test_port_isolation_rejects_different_port(temp_eng_dir):
    """Test 6: Port isolation — http://127.0.0.1:3000 must reject port 9999."""
    from nyx.security.authorization import is_hostname_in_scope
    scope = ["http://127.0.0.1:3000"]
    assert is_hostname_in_scope("http://127.0.0.1:3000", scope_list=scope) is True
    assert is_hostname_in_scope("http://127.0.0.1:3000/api/v1", scope_list=scope) is True
    assert is_hostname_in_scope("http://127.0.0.1:9999", scope_list=scope) is False
    assert is_hostname_in_scope("127.0.0.1:9999", scope_list=scope) is False


def test_host_isolation_rejects_different_host_on_same_port(temp_eng_dir):
    """Test 7: Host isolation — http://127.0.0.1:3000 must reject evil.com:3000."""
    from nyx.security.authorization import is_hostname_in_scope
    scope = ["http://127.0.0.1:3000"]
    assert is_hostname_in_scope("http://evil.com:3000", scope_list=scope) is False
    assert is_hostname_in_scope("evil.com:3000", scope_list=scope) is False


def test_scheme_isolation_rejects_mismatched_scheme(temp_eng_dir):
    """Test 8: Scheme isolation — explicit http:// must reject https:// on same port."""
    from nyx.security.authorization import is_hostname_in_scope
    scope = ["http://127.0.0.1:3000"]
    assert is_hostname_in_scope("https://127.0.0.1:3000", scope_list=scope) is False


def test_wildcard_domain_isolation_rejects_typosquats(temp_eng_dir):
    """Test 9: Wildcard domain isolation — *.example.com must reject typosquats."""
    from nyx.security.authorization import is_hostname_in_scope
    scope = ["*.example.com"]
    assert is_hostname_in_scope("api.example.com", scope_list=scope) is True
    assert is_hostname_in_scope("example.com", scope_list=scope) is True
    assert is_hostname_in_scope("evil-example.com", scope_list=scope) is False
    assert is_hostname_in_scope("notexample.com", scope_list=scope) is False


def test_ip_exact_isolation(temp_eng_dir):
    """Test 10: IP address exact matching."""
    from nyx.security.authorization import is_hostname_in_scope
    scope = ["127.0.0.1"]
    assert is_hostname_in_scope("127.0.0.1", scope_list=scope) is True
    assert is_hostname_in_scope("127.0.0.2", scope_list=scope) is False


def test_explicit_exclusion_takes_precedence(temp_eng_dir):
    """Test 11: Explicit exclusion takes precedence over wildcard scope."""
    from nyx.security.authorization import is_hostname_in_scope
    eng_dir = temp_eng_dir / ".engagement"
    (eng_dir / "target.yaml").write_text(
        "target:\n  name: example.com\n  scope:\n    - '*.example.com'\n  exclusions:\n    - 'admin.example.com'\n",
        encoding="utf-8"
    )
    assert is_hostname_in_scope("app.example.com", base_dir=temp_eng_dir) is True
    assert is_hostname_in_scope("admin.example.com", base_dir=temp_eng_dir) is False

