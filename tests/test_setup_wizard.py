"""
Tests for NYX Setup & Onboarding Wizard
Verifies dependency checks, idempotency, API key validation/rejection, and .env safety.
"""
from pathlib import Path
import os
import pytest
from nyx.setup_wizard import (
    PlatformDetector,
    DependencyInstaller,
    AIProviderConfigurator,
    SetupWizard,
)


def test_platform_detector():
    info = PlatformDetector.get_info()
    assert "os" in info
    assert "os_label" in info
    assert "python_version" in info
    assert isinstance(info["is_wsl"], bool)


def test_dependency_installer_python_check(tmp_path: Path):
    installer = DependencyInstaller(base_dir=tmp_path)
    ok, msg = installer.check_python_version()
    # Python running pytest is >= 3.11
    assert ok is True
    assert "Python" in msg


def test_ai_provider_configurator_key_rejection(tmp_path: Path, monkeypatch):
    """Test that invalid API key is rejected by test_key_live and not accepted."""
    configurator = AIProviderConfigurator(base_dir=tmp_path)

    # Test with obviously bogus key
    bogus_key = "gsk_invalid_bogus_key_12345678901234567890"
    ok, msg = configurator.test_key_live("groq", bogus_key)
    assert ok is False
    assert len(msg) > 0


def test_ai_provider_configurator_write_and_backup(tmp_path: Path):
    """Test that write_env_variables safely writes and backups existing .env."""
    configurator = AIProviderConfigurator(base_dir=tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING_VAR=123\nGROQ_API_KEY=old_key\n", encoding="utf-8")

    # Create backup
    backup_p = configurator.backup_env_file()
    assert backup_p is not None
    assert backup_p.exists()
    assert "old_key" in backup_p.read_text(encoding="utf-8")

    # Write new variables
    configurator.write_env_variables(
        {"GROQ_API_KEY": "new_validated_key", "GEMINI_API_KEY": "gemini_key_456"},
        default_provider="groq",
    )

    new_content = env_file.read_text(encoding="utf-8")
    assert "GROQ_API_KEY=new_validated_key" in new_content
    assert "GEMINI_API_KEY=gemini_key_456" in new_content
    assert "EXISTING_VAR=123" in new_content
    assert "NYX_AI_PROVIDER=groq" in new_content


def test_dependency_installer_idempotency(tmp_path: Path):
    """Test that running checks multiple times is idempotent and non-destructive."""
    installer = DependencyInstaller(base_dir=tmp_path)
    ok1, msg1 = installer.check_python_version()
    ok2, msg2 = installer.check_python_version()
    assert ok1 == ok2
    assert msg1 == msg2


def test_setup_wizard_consent_refusal(tmp_path: Path, monkeypatch):
    """Test that refusing authorization consent aborts setup."""
    wizard = SetupWizard(base_dir=tmp_path, non_interactive=False)

    # Simulate typing 'NO' to consent
    monkeypatch.setattr("builtins.input", lambda prompt="": "NO")
    consent_ok = wizard.run_authorization_consent_step()
    assert consent_ok is False
