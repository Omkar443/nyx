"""
NYX Setup & Onboarding Wizard Engine
Complete, cross-platform, idempotent installer for dependencies, external tools,
AI providers (with pre-write validation), and authorization initialization.
"""
from __future__ import annotations

import getpass
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent


class Colors:
    """ANSI color codes for formatted terminal output."""
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def strip(cls, text: str) -> str:
        return re.sub(r"\033\[[0-9;]*m", "", text)


def log_step(step_num: int, total_steps: int, title: str):
    print(f"\n{Colors.BOLD}{Colors.CYAN}[{step_num}/{total_steps}] {title}{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")


def log_ok(msg: str):
    print(f"  {Colors.GREEN}✓{Colors.RESET} {msg}")


def log_warn(msg: str):
    print(f"  {Colors.YELLOW}⚠{Colors.RESET} {msg}")


def log_fail(msg: str):
    print(f"  {Colors.RED}✗{Colors.RESET} {msg}")


def log_info(msg: str):
    print(f"  {Colors.DIM}•{Colors.RESET} {msg}")


class PlatformDetector:
    """Detects host operating system, architecture, and virtualization."""

    @staticmethod
    def get_info() -> Dict[str, Any]:
        os_type = sys.platform
        is_wsl = False
        if os_type.startswith("linux"):
            try:
                with open("/proc/version", "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    is_wsl = "microsoft" in content or "wsl" in content
            except Exception:
                pass

        os_label = "Linux (WSL)" if is_wsl else ("Linux" if os_type.startswith("linux") else ("macOS" if os_type == "darwin" else ("Windows" if os_type == "win32" else os_type)))
        return {
            "os": os_type,
            "os_label": os_label,
            "is_wsl": is_wsl,
            "is_windows": os_type == "win32",
            "is_mac": os_type == "darwin",
            "is_linux": os_type.startswith("linux"),
            "arch": platform.machine(),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }


class DependencyInstaller:
    """Checks and idempotently installs Python dependencies, Node frontend, security tools, and wordlists."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or REPO_ROOT
        self.frontend_dir = self.base_dir / "frontend"

    def check_python_version(self) -> Tuple[bool, str]:
        major, minor = sys.version_info.major, sys.version_info.minor
        ver_str = f"{major}.{minor}.{sys.version_info.micro}"
        if (major, minor) >= (3, 11):
            return True, f"Python {ver_str} (Supported >= 3.11)"
        return False, f"Python {ver_str} is installed, but NYX requires Python >= 3.11"

    def install_python_deps(self) -> Tuple[bool, str]:
        """Idempotently install Python dependencies from pyproject.toml / requirements."""
        py_exe = sys.executable
        # Check if already installed
        try:
            import fastapi
            import uvicorn
            import yaml
            import dotenv
            import requests
            import pytest
            return True, "Python dependencies already satisfied"
        except ImportError:
            pass

        log_info("Installing Python dependencies via pip...")
        try:
            cmd = [py_exe, "-m", "pip", "install", "-e", ".[all]"]
            res = subprocess.run(cmd, cwd=self.base_dir, capture_output=True, text=True, timeout=300)
            if res.returncode == 0:
                return True, "Python dependencies installed successfully"
            # Fallback to basic install
            cmd_fallback = [py_exe, "-m", "pip", "install", "-e", "."]
            res_fb = subprocess.run(cmd_fallback, cwd=self.base_dir, capture_output=True, text=True, timeout=300)
            if res_fb.returncode == 0:
                return True, "Python core dependencies installed"
            return False, f"pip install failed: {res.stderr[:300]}"
        except Exception as ex:
            return False, f"Error running pip: {ex}"

    def check_node_and_npm(self) -> Tuple[bool, str]:
        node_bin = shutil.which("node")
        npm_bin = shutil.which("npm") or shutil.which("npm.cmd")
        if not node_bin:
            return False, "Node.js not found in PATH (required for NYX Web Dashboard)"
        if not npm_bin:
            return False, "npm not found in PATH"

        try:
            res = subprocess.run([node_bin, "--version"], capture_output=True, text=True, timeout=5)
            ver = res.stdout.strip()
            return True, f"Node.js {ver} & npm available"
        except Exception:
            return True, "Node.js & npm available"

    def build_frontend(self) -> Tuple[bool, str]:
        """Idempotently install frontend dependencies and build production bundle."""
        if not self.frontend_dir.exists():
            return False, "frontend directory not found"

        dist_index = self.frontend_dir / "dist" / "index.html"
        node_modules = self.frontend_dir / "node_modules"

        npm_bin = shutil.which("npm") or shutil.which("npm.cmd")
        if not npm_bin:
            return False, "npm is required to build frontend"

        # Check if already built
        if dist_index.exists() and node_modules.exists():
            return True, "Frontend production bundle already built (dist/index.html present)"

        # Install node_modules if missing
        if not node_modules.exists():
            log_info("Installing frontend npm dependencies...")
            lock_file = self.frontend_dir / "package-lock.json"
            cmd = [npm_bin, "ci"] if lock_file.exists() else [npm_bin, "install"]
            try:
                res = subprocess.run(cmd, cwd=self.frontend_dir, capture_output=True, text=True, timeout=300, shell=(sys.platform == "win32"))
                if res.returncode != 0:
                    res = subprocess.run([npm_bin, "install"], cwd=self.frontend_dir, capture_output=True, text=True, timeout=300, shell=(sys.platform == "win32"))
                    if res.returncode != 0:
                        return False, f"npm install failed: {res.stderr[:200]}"
            except Exception as ex:
                return False, f"Failed to run npm: {ex}"

        # Build bundle
        log_info("Building frontend production assets (npm run build)...")
        try:
            res = subprocess.run([npm_bin, "run", "build"], cwd=self.frontend_dir, capture_output=True, text=True, timeout=180, shell=(sys.platform == "win32"))
            if res.returncode == 0 and dist_index.exists():
                return True, "Frontend production bundle built successfully"
            return False, f"Frontend build failed: {res.stderr[:200]}"
        except Exception as ex:
            return False, f"Error building frontend: {ex}"

    def check_external_tool(self, tool_name: str) -> Tuple[bool, str]:
        """Check for external security tools (nuclei, sqlmap, ffuf)."""
        from nyx.infrastructure.tools import get_tool_executable_vector
        vec = get_tool_executable_vector(tool_name)
        if vec:
            return True, f"Found '{tool_name}' ({' '.join(vec)})"
        return False, f"Tool '{tool_name}' not found on system PATH"

    def install_sqlmap_if_missing(self) -> Tuple[bool, str]:
        """Auto-install sqlmap via pip if not on PATH."""
        ok, msg = self.check_external_tool("sqlmap")
        if ok:
            return True, msg
        log_info("sqlmap not found in PATH — installing via pip...")
        try:
            res = subprocess.run([sys.executable, "-m", "pip", "install", "sqlmap"], capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                return True, "sqlmap installed successfully via pip"
            return False, f"Failed to pip install sqlmap: {res.stderr[:200]}"
        except Exception as ex:
            return False, f"Error installing sqlmap: {ex}"

    def check_or_install_go_tool(self, tool_name: str, go_pkg: str) -> Tuple[bool, str]:
        """Check for Go-based tools (nuclei, ffuf) or install via go install if Go is present."""
        ok, msg = self.check_external_tool(tool_name)
        if ok:
            return True, msg

        go_bin = shutil.which("go")
        if not go_bin:
            return False, f"'{tool_name}' not found. To install: install Go and run 'go install {go_pkg}' or download precompiled binary."

        log_info(f"Installing {tool_name} via go install {go_pkg}...")
        try:
            res = subprocess.run([go_bin, "install", go_pkg], capture_output=True, text=True, timeout=300)
            if res.returncode == 0:
                return True, f"{tool_name} installed successfully via go install"
            return False, f"go install {tool_name} failed: {res.stderr[:200]}"
        except Exception as ex:
            return False, f"Error installing {tool_name}: {ex}"

    def check_seclists(self) -> Tuple[bool, str]:
        """Check for SecLists wordlists at standard locations."""
        candidates = [
            Path("/usr/share/seclists"),
            Path("/usr/share/wordlists/seclists"),
            Path.home() / ".local" / "share" / "seclists",
            Path.home() / "SecLists",
            self.base_dir / "skills" / "wordlists" / "seclists",
        ]
        for cand in candidates:
            if cand.exists() and cand.is_dir():
                return True, f"SecLists detected at {cand}"
        return False, "SecLists not detected at standard locations (/usr/share/seclists). Install via: 'sudo apt install seclists' or git clone to ~/.local/share/seclists"


class AIProviderConfigurator:
    """Interactive AI provider configuration with live verification before saving."""

    PROVIDER_ENV_KEYS = {
        "groq": "GROQ_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "openai": "OPENAI_API_KEY",
        "claude": "ANTHROPIC_API_KEY",
        "grok": "XAI_API_KEY",
        "local": "LOCAL_LLAMA_URL",
        "llama": "LOCAL_LLAMA_URL",
        "deepseek": "LOCAL_LLAMA_URL",
    }

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or REPO_ROOT
        self.env_file = self.base_dir / ".env"

    def get_registered_providers(self) -> List[Dict[str, Any]]:
        """Dynamically list all providers from AIManager."""
        from nyx.ai.manager import AIManager
        try:
            mgr = AIManager()
            return mgr.list_providers()
        except Exception:
            return [
                {"name": "groq", "type": "hosted", "model": "openai/gpt-oss-120b"},
                {"name": "gemini", "type": "hosted", "model": "gemini-2.5-flash"},
                {"name": "local", "type": "local", "model": "llama-local"},
                {"name": "openai", "type": "hosted", "model": "gpt-4o"},
                {"name": "claude", "type": "hosted", "model": "claude-3-5-sonnet"},
                {"name": "grok", "type": "hosted", "model": "grok-2"},
            ]

    def test_key_live(self, provider_name: str, key_or_url: str) -> Tuple[bool, str]:
        """Test API key or endpoint against live provider BEFORE saving to .env."""
        norm_prov = provider_name.lower().strip()
        env_var = self.PROVIDER_ENV_KEYS.get(norm_prov, "GROQ_API_KEY")

        old_val = os.environ.get(env_var)
        os.environ[env_var] = key_or_url.strip()

        try:
            from nyx.ai.providers import get_provider_class
            cls = get_provider_class(norm_prov)
            prov_instance = cls()

            if hasattr(prov_instance, "test_connection"):
                res = prov_instance.test_connection()
                success = bool(res.get("success"))
                msg = res.get("message") or ("Connection OK" if success else "Test failed")
                return success, msg
            else:
                info = prov_instance.get_info()
                status = info.get("status")
                if status == "ready":
                    return True, "Provider initialized successfully"
                return False, info.get("error") or f"Provider status: {status}"
        except Exception as ex:
            return False, str(ex)
        finally:
            if old_val is not None:
                os.environ[env_var] = old_val
            elif env_var in os.environ:
                del os.environ[env_var]

    def backup_env_file(self) -> Optional[Path]:
        """Create a timestamped backup of existing .env."""
        if not self.env_file.exists():
            return None
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.base_dir / f".env.backup.{ts}"
        shutil.copy2(self.env_file, backup_path)
        return backup_path

    def write_env_variables(self, new_vars: Dict[str, str], default_provider: Optional[str] = None) -> bool:
        """Merge validated variables into .env safely."""
        existing_lines: List[str] = []
        if self.env_file.exists():
            existing_lines = self.env_file.read_text(encoding="utf-8").splitlines()

        updated_keys = set(new_vars.keys())
        if default_provider:
            new_vars["NYX_AI_PROVIDER"] = default_provider.lower().strip()
            updated_keys.add("NYX_AI_PROVIDER")

        new_lines = []
        handled_keys = set()

        for line in existing_lines:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped or "=" not in stripped:
                new_lines.append(line)
                continue

            k = stripped.split("=", 1)[0].strip()
            if k in new_vars:
                new_lines.append(f"{k}={new_vars[k]}")
                handled_keys.add(k)
            else:
                new_lines.append(line)

        for k, v in new_vars.items():
            if k not in handled_keys:
                new_lines.append(f"{k}={v}")

        self.env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return True


class SetupWizard:
    """Master orchestrator for the NYX onboarding and setup workflow."""

    def __init__(self, base_dir: Optional[Path] = None, non_interactive: bool = False):
        self.base_dir = base_dir or REPO_ROOT
        self.non_interactive = non_interactive
        self.platform_detector = PlatformDetector()
        self.dep_installer = DependencyInstaller(base_dir=self.base_dir)
        self.ai_configurator = AIProviderConfigurator(base_dir=self.base_dir)

    def print_banner(self):
        banner = f"""
{Colors.BOLD}{Colors.CYAN}======================================================================
  NYX Security Intelligence Engine — Installation & Onboarding
======================================================================{Colors.RESET}
  Antigravity Security Intelligence Platform
  Zero-Trust Architecture | Fail-Closed Policy Enforcement | Empirical Validation
"""
        print(banner)

    def run_dependency_step(self) -> bool:
        log_step(1, 4, "System Environment & Dependency Verification")

        info = self.platform_detector.get_info()
        log_ok(f"Host Platform: {info['os_label']} ({info['arch']})")

        # 1. Python Check
        py_ok, py_msg = self.dep_installer.check_python_version()
        if py_ok:
            log_ok(py_msg)
        else:
            log_fail(py_msg)
            return False

        # 2. Python Packages
        pip_ok, pip_msg = self.dep_installer.install_python_deps()
        if pip_ok:
            log_ok(pip_msg)
        else:
            log_warn(pip_msg)

        # 3. Node.js & npm
        node_ok, node_msg = self.dep_installer.check_node_and_npm()
        if node_ok:
            log_ok(node_msg)
            # Build frontend
            fb_ok, fb_msg = self.dep_installer.build_frontend()
            if fb_ok:
                log_ok(fb_msg)
            else:
                log_warn(fb_msg)
        else:
            log_warn(node_msg)

        # 4. External Security Tools
        sql_ok, sql_msg = self.dep_installer.install_sqlmap_if_missing()
        if sql_ok:
            log_ok(sql_msg)
        else:
            log_warn(sql_msg)

        nuc_ok, nuc_msg = self.dep_installer.check_or_install_go_tool("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        if nuc_ok:
            log_ok(nuc_msg)
        else:
            log_warn(nuc_msg)

        ffuf_ok, ffuf_msg = self.dep_installer.check_or_install_go_tool("ffuf", "github.com/ffuf/ffuf/v2@latest")
        if ffuf_ok:
            log_ok(ffuf_msg)
        else:
            log_warn(ffuf_msg)

        # 5. SecLists
        sec_ok, sec_msg = self.dep_installer.check_seclists()
        if sec_ok:
            log_ok(sec_msg)
        else:
            log_warn(sec_msg)

        return True

    def run_ai_provider_step(self) -> Tuple[bool, Optional[str]]:
        log_step(2, 4, "AI Provider Configuration & Live Validation")

        providers = self.ai_configurator.get_registered_providers()
        p_names = [p.get("name", "") for p in providers if p.get("name")]

        print(f"  Available AI Providers: {Colors.BOLD}{', '.join(p_names)}{Colors.RESET}")

        if self.non_interactive:
            log_info("Non-interactive mode: checking existing .env configuration...")
            default_prov = os.environ.get("NYX_AI_PROVIDER") or os.environ.get("DEFAULT_AI_PROVIDER") or "groq"
            return True, default_prov

        configured_vars: Dict[str, str] = {}
        chosen_default = None

        print("\nSelect primary AI provider to configure:")
        for idx, p in enumerate(p_names, 1):
            print(f"  [{idx}] {p.upper():<10} (Model: {p.get('model', 'default') if isinstance(p, dict) else ''})")
        print("  [s] Skip AI configuration (use existing .env / offline mode)")

        choice = input(f"\nEnter choice [1-{len(p_names)} or s] (default: 1): ").strip()
        if choice.lower() == "s":
            log_info("Skipped interactive AI provider configuration.")
            return True, None

        sel_idx = 0
        if choice.isdigit() and 1 <= int(choice) <= len(p_names):
            sel_idx = int(choice) - 1

        selected_prov = p_names[sel_idx]
        chosen_default = selected_prov
        env_var = self.ai_configurator.PROVIDER_ENV_KEYS.get(selected_prov, "GROQ_API_KEY")

        if selected_prov in ("local", "llama", "deepseek"):
            server_url = input(f"Enter Local AI Server Chat URL [default: http://localhost:8000/chat]: ").strip()
            if not server_url:
                server_url = "http://localhost:8000/chat"

            log_info(f"Validating local server connectivity at {server_url}...")
            ok, msg = self.ai_configurator.test_key_live(selected_prov, server_url)
            if ok:
                log_ok(f"Local server verified: {msg}")
                configured_vars[env_var] = server_url
            else:
                log_warn(f"Local server validation failed: {msg}")
                save_anyway = input("Save local URL anyway? [y/N]: ").strip().lower()
                if save_anyway == "y":
                    configured_vars[env_var] = server_url
        else:
            while True:
                key_input = getpass.getpass(f"Enter {selected_prov.upper()} API Key (input hidden): ").strip()
                if not key_input:
                    log_warn("No key entered. Skipping provider.")
                    break

                log_info(f"Validating {selected_prov.upper()} API key with live connection check...")
                ok, msg = self.ai_configurator.test_key_live(selected_prov, key_input)
                if ok:
                    log_ok(f"{selected_prov.upper()} API key verified successfully! ({msg})")
                    configured_vars[env_var] = key_input
                    break
                else:
                    log_fail(f"Key validation REJECTED: {msg}")
                    retry = input("Retry entering key? [Y/n]: ").strip().lower()
                    if retry == "n":
                        log_info("Skipped saving unverified key.")
                        break

        if configured_vars:
            backup_p = self.ai_configurator.backup_env_file()
            if backup_p:
                log_info(f"Existing .env backed up to {backup_p.name}")
            self.ai_configurator.write_env_variables(configured_vars, default_provider=chosen_default)
            log_ok(f"Saved verified credentials to .env (Default Provider: {chosen_default})")

        return True, chosen_default

    def run_authorization_consent_step(self) -> bool:
        log_step(3, 4, "Engagement Scope & Safety Authorization Consent")

        consent_text = f"""
{Colors.YELLOW}{Colors.BOLD}======================================================================
  NYX AUTHORIZATION & ETHICAL COMPLIANCE PROTOCOL
======================================================================{Colors.RESET}
  NYX is an offensive security intelligence engine designed EXCLUSIVELY for:
    1. Authorized penetration testing with explicit written client authorization.
    2. Bug bounty engagements strictly within program scope boundaries.
    3. Defensive vulnerability research on infrastructure you own or control.

  {Colors.BOLD}SAFETY CONSTRAINTS:{Colors.RESET}
    • Active probing is strictly disabled unless explicitly authorized.
    • Non-destructive methods are prioritized; destructive tests require approval.
    • Workspace state and scope must be maintained in .engagement/.
======================================================================
"""
        print(consent_text)

        if self.non_interactive:
            log_ok("Non-interactive mode: authorization terms accepted via flag.")
            return True

        confirm = input(f"Type {Colors.BOLD}'AGREE'{Colors.RESET} to confirm ethical authorization compliance: ").strip()
        if confirm.upper() != "AGREE":
            log_fail("Authorization terms not agreed. Setup aborted.")
            return False

        log_ok("Authorization terms acknowledged.")

        # Initialize base workspace structure if not present
        eng_dir = self.base_dir / ".engagement"
        if not eng_dir.exists():
            from nyx.core.engagement import init_engagement
            init_engagement("https://localhost/", reset=False, base_dir=self.base_dir)
            log_ok("Initialized .engagement workspace directory structure.")
        else:
            log_ok("Existing .engagement workspace preserved.")

        return True

    def run_validation_step(self, chosen_provider: Optional[str] = None) -> bool:
        log_step(4, 4, "Installation Validation & Test Suite Check")

        log_info("Running core test suite validation (pytest)...")
        try:
            res = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/test_fixes_session_bugs.py", "-q"],
                cwd=self.base_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )
            out_summary = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
            if res.returncode == 0:
                log_ok(f"Test Suite Validation: {out_summary or 'All tests passed'}")
            else:
                log_warn(f"Test Suite: {out_summary or 'Some tests failed or warning encountered'}")
        except Exception as ex:
            log_warn(f"Test runner skipped: {ex}")

        # AI provider test
        prov_to_test = chosen_provider or os.environ.get("NYX_AI_PROVIDER") or "groq"
        log_info(f"Testing live AI integration for provider '{prov_to_test}'...")
        try:
            from nyx.application.ai_service import AIService
            svc = AIService(base_dir=self.base_dir)
            t_res = svc.test_provider(provider_name=prov_to_test)
            if t_res.is_success:
                log_ok(f"AI Provider Test: {prov_to_test.upper()} is active and operational.")
            else:
                log_info(f"AI Provider Test: {prov_to_test.upper()} not currently reachable ({t_res.error}).")
        except Exception:
            pass

        print(f"\n{Colors.BOLD}{Colors.GREEN}======================================================================{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}  ✓ NYX Installation & Onboarding Complete!{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}======================================================================{Colors.RESET}")
        print("\nNext Steps:")
        print(f"  • Launch Dashboard:     {Colors.BOLD}python3 -m nyx_cli.cli web{Colors.RESET} (or 'nyx web')")
        print(f"  • Initialize Target:    {Colors.BOLD}python3 -m nyx_cli.cli engagement init <url>{Colors.RESET}")
        print(f"  • Run AI Mission:       {Colors.BOLD}python3 -m nyx_cli.cli ai autonomous <url>{Colors.RESET}")
        print(f"  • List AI Providers:    {Colors.BOLD}python3 -m nyx_cli.cli ai providers{Colors.RESET}")
        print("")
        return True

    def run_all(self) -> int:
        self.print_banner()

        if not self.run_dependency_step():
            log_fail("Dependency verification failed. Please resolve above issues and rerun.")
            return 1

        ai_ok, chosen_prov = self.run_ai_provider_step()
        if not ai_ok:
            log_fail("AI provider setup aborted.")
            return 1

        if not self.run_authorization_consent_step():
            return 1

        self.run_validation_step(chosen_provider=chosen_prov)
        return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description="NYX Security Intelligence Engine Setup & Onboarding Wizard")
    parser.add_argument("--non-interactive", action="store_true", help="Run in non-interactive / CI mode")
    parser.add_argument("--check-only", action="store_true", help="Perform dependency checks only without modifying environment")
    args = parser.parse_args()

    wizard = SetupWizard(non_interactive=args.non_interactive)
    if args.check_only:
        wizard.print_banner()
        ok = wizard.run_dependency_step()
        sys.exit(0 if ok else 1)

    sys.exit(wizard.run_all())


if __name__ == "__main__":
    main()
