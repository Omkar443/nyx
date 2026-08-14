"""
NYX First-Run Dependency Bootstrap & Environment Validation Test Suite
"""
import os
import sys
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from nyx.infrastructure.environment import PlatformInfo, DependencyProfile, BootstrapLock
from nyx.infrastructure.dependencies import (
    PythonDependencyManager,
    NodeDependencyManager,
    FrontendBuildManager,
    BootstrapManager,
)


@pytest.fixture
def temp_workspace():
    tmp_dir = Path(tempfile.mkdtemp(prefix="nyx_bootstrap_test_"))
    orig_cwd = os.getcwd()
    os.chdir(tmp_dir)
    yield tmp_dir
    os.chdir(orig_cwd)
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_python_detection():
    """Test 1: Python executable detection."""
    cmd = PlatformInfo.get_python_cmd()
    assert cmd is not None
    assert isinstance(cmd, str)
    assert len(cmd) > 0


def test_python_version_validation():
    """Test 2: Python version validation."""
    assert PlatformInfo.is_python_valid((3, 9)) is True
    assert PlatformInfo.is_python_valid((4, 0)) is False


def test_pip_detection():
    """Test 3: pip detection."""
    mgr = PythonDependencyManager()
    res = mgr.check_pip()
    assert res["name"] == "pip"
    assert res["status"] in ("OK", "FAIL")


def test_python_dependency_detection():
    """Test 4: Python package dependency detection."""
    mgr = PythonDependencyManager()
    res = mgr.check_packages()
    assert res["name"] == "Python packages"
    assert "status" in res


def test_node_detection():
    """Test 5: Node.js detection."""
    mgr = NodeDependencyManager()
    res = mgr.check_node()
    assert res["name"] == "Node.js"
    assert "status" in res


def test_npm_detection():
    """Test 6: npm detection."""
    mgr = NodeDependencyManager()
    res = mgr.check_npm()
    assert res["name"] == "npm"
    assert "status" in res


def test_frontend_dependency_detection(temp_workspace):
    """Test 7: Frontend node_modules dependency detection."""
    frontend_dir = temp_workspace / "frontend"
    frontend_dir.mkdir(parents=True, exist_ok=True)
    mgr = NodeDependencyManager(base_dir=temp_workspace)

    res_missing = mgr.check_frontend_deps()
    assert res_missing["status"] == "MISSING"

    react_dir = frontend_dir / "node_modules" / "react"
    react_dir.mkdir(parents=True, exist_ok=True)

    res_ok = mgr.check_frontend_deps()
    assert res_ok["status"] == "OK"


def test_frontend_build_detection(temp_workspace):
    """Test 8: Frontend production build detection."""
    frontend_dir = temp_workspace / "frontend"
    dist_dir = frontend_dir / "dist"
    frontend_dir.mkdir(parents=True, exist_ok=True)
    mgr = FrontendBuildManager(base_dir=temp_workspace)

    res_missing = mgr.check_build()
    assert res_missing["status"] == "MISSING"

    dist_dir.mkdir(parents=True, exist_ok=True)
    (dist_dir / "index.html").write_text("<html></html>", encoding="utf-8")

    res_ok = mgr.check_build()
    assert res_ok["status"] == "OK"


@patch("subprocess.run")
def test_missing_dependency_installation(mock_run, temp_workspace):
    """Test 9: Automatic installation of missing dependencies."""
    mock_run.return_value = MagicMock(returncode=0, stdout="v22.0.0")

    py_mgr = PythonDependencyManager(base_dir=temp_workspace)
    ok_py = py_mgr.install_packages()
    assert ok_py is True

    node_mgr = NodeDependencyManager(base_dir=temp_workspace)
    (temp_workspace / "frontend").mkdir(exist_ok=True)
    with patch("shutil.which", return_value="/usr/bin/npm"):
        ok_node = node_mgr.install_frontend_deps()
        assert ok_node is True


def test_already_installed_dependency_is_not_reinstalled(temp_workspace):
    """Test 10: Idempotency skips already installed dependencies."""
    mgr = BootstrapManager(base_dir=temp_workspace)
    with patch.object(mgr.py_mgr, "check_python", return_value={"name": "Python", "status": "OK"}), \
         patch.object(mgr.py_mgr, "check_pip", return_value={"name": "pip", "status": "OK"}), \
         patch.object(mgr.py_mgr, "check_packages", return_value={"name": "Python packages", "status": "OK"}), \
         patch.object(mgr.node_mgr, "check_node", return_value={"name": "Node.js", "status": "OK"}), \
         patch.object(mgr.node_mgr, "check_npm", return_value={"name": "npm", "status": "OK"}), \
         patch.object(mgr.node_mgr, "check_frontend_deps", return_value={"name": "Frontend deps", "status": "OK"}), \
         patch.object(mgr.build_mgr, "check_build", return_value={"name": "Frontend build", "status": "OK"}), \
         patch.object(mgr.py_mgr, "install_packages") as mock_py_inst, \
         patch.object(mgr.node_mgr, "install_frontend_deps") as mock_node_inst:

        res = mgr.ensure_environment(profile=DependencyProfile.WEB, silent=True)
        assert res["ready"] is True
        mock_py_inst.assert_not_called()
        mock_node_inst.assert_not_called()


@patch("subprocess.run")
def test_installation_failure_handling(mock_run, temp_workspace):
    """Test 11: Installation failure handling."""
    mock_run.return_value = MagicMock(returncode=1, stderr="Failed to install")

    py_mgr = PythonDependencyManager(base_dir=temp_workspace)
    ok = py_mgr.install_packages()
    assert ok is False


def test_dependency_profile_core(temp_workspace):
    """Test 12: CORE profile runs only Python checks."""
    mgr = BootstrapManager(base_dir=temp_workspace)
    checks = mgr.run_preflight_checks(profile=DependencyProfile.CORE)
    names = [c["name"] for c in checks]

    assert "Python" in names
    assert "pip" in names
    assert "Python packages" in names
    assert "Node.js" not in names
    assert "Frontend build" not in names


def test_dependency_profile_web(temp_workspace):
    """Test 13: WEB profile runs both CORE and Web/Frontend checks."""
    mgr = BootstrapManager(base_dir=temp_workspace)
    checks = mgr.run_preflight_checks(profile=DependencyProfile.WEB)
    names = [c["name"] for c in checks]

    assert "Python" in names
    assert "Node.js" in names
    assert "npm" in names
    assert "Frontend deps" in names
    assert "Frontend build" in names


def test_doctor_environment_report(temp_workspace):
    """Test 14: Doctor environment report structure."""
    mgr = BootstrapManager(base_dir=temp_workspace)
    checks = mgr.run_preflight_checks(profile=DependencyProfile.WEB)
    assert len(checks) >= 7


def test_workspace_is_never_deleted(temp_workspace):
    """Test 15: SAFEGUARD check ensuring user workspace is never deleted."""
    eng_dir = temp_workspace / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)
    target_file = eng_dir / "target.yaml"
    target_file.write_text("target: example.com\n", encoding="utf-8")

    mgr = BootstrapManager(base_dir=temp_workspace)
    mgr.ensure_environment(profile=DependencyProfile.WEB, silent=True)

    assert eng_dir.exists()
    assert target_file.exists()
    assert target_file.read_text(encoding="utf-8") == "target: example.com\n"


def test_bootstrap_is_idempotent(temp_workspace):
    """Test 16: Bootstrap operation idempotency."""
    mgr = BootstrapManager(base_dir=temp_workspace)
    with patch.object(mgr, "run_preflight_checks", return_value=[{"name": "Python", "status": "OK"}]):
        res1 = mgr.ensure_environment(profile=DependencyProfile.CORE, silent=True)
        res2 = mgr.ensure_environment(profile=DependencyProfile.CORE, silent=True)

        assert res1["ready"] is True
        assert res2["ready"] is True
