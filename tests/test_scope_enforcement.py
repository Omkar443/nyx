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
