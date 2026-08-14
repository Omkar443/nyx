"""
NYX Dependency Bootstrap & Environment Validation Manager
"""
from __future__ import annotations

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from nyx.infrastructure.environment import PlatformInfo, DependencyProfile, BootstrapLock, print_preflight_banner


class PythonDependencyManager:
    """Python runtime & pip package installer manager."""

    REQUIRED_PACKAGES = ["fastapi", "uvicorn", "requests", "setuptools"]

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path.cwd()

    def check_python(self) -> Dict[str, Any]:
        valid = PlatformInfo.is_python_valid()
        version = PlatformInfo.get_python_version()
        return {
            "name": "Python",
            "status": "OK" if valid else "FAIL",
            "version": version,
            "executable": PlatformInfo.get_python_cmd(),
            "detail": f"v{version}",
        }

    def check_pip(self) -> Dict[str, Any]:
        py_cmd = PlatformInfo.get_python_cmd()
        try:
            res = subprocess.run([py_cmd, "-m", "pip", "--version"], capture_output=True, text=True, timeout=10)
            ok = (res.returncode == 0)
            return {
                "name": "pip",
                "status": "OK" if ok else "FAIL",
                "detail": res.stdout.split()[1] if ok and len(res.stdout.split()) > 1 else ("Available" if ok else "Missing"),
            }
        except Exception:
            return {"name": "pip", "status": "FAIL", "detail": "pip not found"}

    def check_packages(self) -> Dict[str, Any]:
        missing = []
        for pkg in self.REQUIRED_PACKAGES:
            try:
                __import__(pkg)
            except ImportError:
                missing.append(pkg)

        return {
            "name": "Python packages",
            "status": "OK" if not missing else "MISSING",
            "missing": missing,
            "detail": "All installed" if not missing else f"Missing: {', '.join(missing)}",
        }

    def install_packages(self) -> bool:
        py_cmd = PlatformInfo.get_python_cmd()
        cmd = [py_cmd, "-m", "pip", "install", "-e", "."]
        try:
            res = subprocess.run(cmd, cwd=self.base_dir, capture_output=True, text=True, timeout=120)
            return res.returncode == 0
        except Exception:
            return False


class NodeDependencyManager:
    """Node.js, npm, and frontend package manager."""

    MIN_NODE_VERSION = 18

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path.cwd()
        self.frontend_dir = self.base_dir / "frontend"

    def check_node(self) -> Dict[str, Any]:
        node_cmd = shutil.which("node")
        if not node_cmd:
            pms = PlatformInfo.detect_package_managers()
            os_name = PlatformInfo.get_os()
            manual_cmd = "sudo apt update && sudo apt install -y nodejs npm" if os_name in ("linux", "wsl2") else "winget install OpenJS.NodeJS"
            return {
                "name": "Node.js",
                "status": "FAIL",
                "detail": "NOT FOUND",
                "manual_cmd": manual_cmd,
                "package_managers": pms,
            }

        try:
            res = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                ver_str = res.stdout.strip().lstrip("v")
                major = int(ver_str.split(".")[0]) if ver_str and ver_str.split(".")[0].isdigit() else 0
                ok = (major >= self.MIN_NODE_VERSION)
                return {
                    "name": "Node.js",
                    "status": "OK" if ok else "WARN",
                    "version": ver_str,
                    "detail": f"v{ver_str}",
                }
        except Exception:
            pass

        return {"name": "Node.js", "status": "FAIL", "detail": "Execution failed"}

    def check_npm(self) -> Dict[str, Any]:
        npm_cmd = shutil.which("npm")
        if not npm_cmd:
            return {"name": "npm", "status": "FAIL", "detail": "NOT FOUND"}
        try:
            res = subprocess.run(["npm", "--version"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                ver_str = res.stdout.strip()
                return {"name": "npm", "status": "OK", "detail": f"v{ver_str}"}
        except Exception:
            pass
        return {"name": "npm", "status": "FAIL", "detail": "Execution failed"}

    def check_frontend_deps(self) -> Dict[str, Any]:
        modules_dir = self.frontend_dir / "node_modules"
        if not modules_dir.exists():
            return {"name": "Frontend deps", "status": "MISSING", "detail": "node_modules missing"}

        # Quick validity check
        react_dir = modules_dir / "react"
        if not react_dir.exists():
            return {"name": "Frontend deps", "status": "MISSING", "detail": "node_modules incomplete"}

        return {"name": "Frontend deps", "status": "OK", "detail": "Installed"}

    def install_frontend_deps(self) -> bool:
        if not shutil.which("npm"):
            return False
        if not self.frontend_dir.exists():
            return False

        # Prefer npm ci if lockfile exists, else npm install
        lock_file = self.frontend_dir / "package-lock.json"
        cmd = ["npm", "ci"] if lock_file.exists() else ["npm", "install"]
        try:
            res = subprocess.run(cmd, cwd=self.frontend_dir, capture_output=True, text=True, timeout=300)
            if res.returncode == 0:
                return True
            # Fallback to npm install if npm ci fails
            if cmd[1] == "ci":
                res2 = subprocess.run(["npm", "install"], cwd=self.frontend_dir, capture_output=True, text=True, timeout=300)
                return res2.returncode == 0
        except Exception:
            pass
        return False


class FrontendBuildManager:
    """Frontend asset build orchestrator."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path.cwd()
        self.frontend_dir = self.base_dir / "frontend"
        self.dist_dir = self.frontend_dir / "dist"

    def check_build(self) -> Dict[str, Any]:
        index_file = self.dist_dir / "index.html"
        if not index_file.exists():
            return {"name": "Frontend build", "status": "MISSING", "detail": "dist/index.html missing"}
        return {"name": "Frontend build", "status": "OK", "detail": "Built"}

    def build_frontend(self) -> bool:
        if not shutil.which("npm"):
            return False
        if not self.frontend_dir.exists():
            return False

        try:
            res = subprocess.run(["npm", "run", "build"], cwd=self.frontend_dir, capture_output=True, text=True, timeout=180)
            return res.returncode == 0
        except Exception:
            return False


class BootstrapManager:
    """Master Environment Bootstrap & Validation Orchestrator."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path.cwd()
        self.py_mgr = PythonDependencyManager(base_dir=self.base_dir)
        self.node_mgr = NodeDependencyManager(base_dir=self.base_dir)
        self.build_mgr = FrontendBuildManager(base_dir=self.base_dir)

    def run_preflight_checks(self, profile: DependencyProfile = DependencyProfile.WEB) -> List[Dict[str, Any]]:
        checks = []

        # 1. CORE Profile Checks
        checks.append(self.py_mgr.check_python())
        checks.append(self.py_mgr.check_pip())
        checks.append(self.py_mgr.check_packages())

        # 2. WEB Profile Checks
        if profile in (DependencyProfile.WEB, DependencyProfile.DEVELOPMENT):
            checks.append(self.node_mgr.check_node())
            checks.append(self.node_mgr.check_npm())
            checks.append(self.node_mgr.check_frontend_deps())
            checks.append(self.build_mgr.check_build())

        return checks

    def ensure_environment(self, profile: DependencyProfile = DependencyProfile.WEB, silent: bool = False) -> Dict[str, Any]:
        """Idempotently validate and bootstrap NYX dependencies for the given profile."""
        with BootstrapLock():
            # SAFEGUARD check
            # Verify workspace directories are NEVER deleted
            eng_dir = self.base_dir / ".engagement"
            if eng_dir.exists():
                pass # Intentionally preserved

            checks = self.run_preflight_checks(profile=profile)
            needs_action = any(c.get("status") in ("FAIL", "MISSING") for c in checks)

            if not needs_action:
                if not silent:
                    print_preflight_banner(checks, profile_name=profile.value)
                return {"status": "OK", "ready": True, "checks": checks}

            # If action needed, attempt automatic installations
            print("\nNYX Environment Bootstrap — Installing missing dependencies...")

            # 1. Python packages
            pkg_check = next((c for c in checks if c["name"] == "Python packages"), {})
            if pkg_check.get("status") == "MISSING":
                print("  • Installing Python dependencies...")
                ok = self.py_mgr.install_packages()
                print(f"    Status: {'✓ Installed' if ok else '✗ Failed'}")

            # 2. Node & npm
            if profile in (DependencyProfile.WEB, DependencyProfile.DEVELOPMENT):
                node_check = next((c for c in checks if c["name"] == "Node.js"), {})
                if node_check.get("status") == "FAIL":
                    print("\n" + "=" * 60)
                    print("  [ERROR] Node.js is required for NYX Dashboard but is missing.")
                    print("  Automatic system installation requires elevated permissions.")
                    print(f"  Please run: {node_check.get('manual_cmd', 'install Node.js')}")
                    print("=" * 60 + "\n")

                # Frontend node_modules
                f_check = next((c for c in checks if c["name"] == "Frontend deps"), {})
                if f_check.get("status") == "MISSING" and shutil.which("npm"):
                    print("  • Installing frontend npm dependencies...")
                    ok = self.node_mgr.install_frontend_deps()
                    print(f"    Status: {'✓ Installed' if ok else '✗ Failed'}")

                # Frontend build
                b_check = next((c for c in checks if c["name"] == "Frontend build"), {})
                if b_check.get("status") == "MISSING" and shutil.which("npm"):
                    print("  • Building frontend production bundle...")
                    ok = self.build_mgr.build_frontend()
                    print(f"    Status: {'✓ Built' if ok else '✗ Failed'}")

            # Final check re-run
            final_checks = self.run_preflight_checks(profile=profile)
            is_ready = all(c.get("status") in ("OK", "WARN") for c in final_checks)
            if not silent:
                print_preflight_banner(final_checks, profile_name=profile.value)

            return {"status": "OK" if is_ready else "PARTIAL", "ready": is_ready, "checks": final_checks}
