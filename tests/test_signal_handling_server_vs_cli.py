"""
Tests for NYX signal handling in server mode (Uvicorn/ASGI) vs CLI mode.
Verifies:
1. Server mode: single Ctrl+C sets _SHUTDOWN_EVENT, terminates subprocesses, returns cleanly (no KeyboardInterrupt).
2. Server mode: post-shutdown re-raise from Uvicorn's capture_signals() is cleanly swallowed.
3. Server mode: double manual Ctrl+C prior to shutdown completion triggers force-exit (os._exit(130)).
4. Plain CLI mode: first Ctrl+C raises KeyboardInterrupt, second triggers force-exit (os._exit(130)).
"""
import os
import signal
import subprocess
import sys
import time
from unittest.mock import patch, MagicMock

import pytest

import nyx.infrastructure.process as proc_module
from nyx.infrastructure.process import (
    _sigint_handler,
    _sigterm_handler,
    set_server_mode,
    is_server_mode,
    mark_server_shutdown_complete,
    is_server_shutdown_complete,
    reset_shutdown,
    is_shutdown_requested,
)


@pytest.fixture(autouse=True)
def clean_state():
    reset_shutdown()
    yield
    reset_shutdown()


def test_server_mode_single_sigint_returns_cleanly():
    """Under server mode, first SIGINT must set shutdown event, terminate subprocesses, and NOT raise KeyboardInterrupt."""
    set_server_mode(True)
    assert is_server_mode() is True
    assert is_shutdown_requested() is False

    with patch.object(proc_module, "terminate_all_subprocesses") as mock_term:
        # Should not raise KeyboardInterrupt
        _sigint_handler(signal.SIGINT, None)

        assert is_shutdown_requested() is True
        mock_term.assert_called_once()


def test_server_mode_post_shutdown_reraise_swallowed():
    """Under server mode, when shutdown is complete, Uvicorn's re-raised SIGINT must be ignored silently."""
    set_server_mode(True)
    mark_server_shutdown_complete()
    assert is_server_shutdown_complete() is True

    with patch.object(proc_module, "terminate_all_subprocesses") as mock_term, \
         patch("os._exit") as mock_exit:
        _sigint_handler(signal.SIGINT, None)
        mock_term.assert_not_called()
        mock_exit.assert_not_called()


def test_server_mode_double_sigint_forces_exit():
    """Under server mode, an actual second Ctrl+C while still shutting down must call os._exit(130)."""
    set_server_mode(True)

    with patch.object(proc_module, "terminate_all_subprocesses"), \
         patch("os._exit") as mock_exit:
        # First Ctrl+C
        _sigint_handler(signal.SIGINT, None)
        mock_exit.assert_not_called()

        # Second Ctrl+C before mark_server_shutdown_complete()
        _sigint_handler(signal.SIGINT, None)
        mock_exit.assert_called_once_with(130)


def test_cli_mode_single_sigint_raises_keyboard_interrupt():
    """Under plain CLI mode (server_mode=False), first Ctrl+C must raise KeyboardInterrupt."""
    set_server_mode(False)
    assert is_server_mode() is False

    with patch.object(proc_module, "terminate_all_subprocesses") as mock_term:
        with pytest.raises(KeyboardInterrupt):
            _sigint_handler(signal.SIGINT, None)

        assert is_shutdown_requested() is True
        mock_term.assert_called_once()


def test_cli_mode_double_sigint_forces_exit():
    """Under plain CLI mode, second Ctrl+C must call os._exit(130)."""
    set_server_mode(False)

    with patch.object(proc_module, "terminate_all_subprocesses"), \
         patch("os._exit") as mock_exit:
        try:
            _sigint_handler(signal.SIGINT, None)
        except KeyboardInterrupt:
            pass

        _sigint_handler(signal.SIGINT, None)
        mock_exit.assert_called_once_with(130)


def test_live_backend_main_single_sigint_clean_exit():
    """Live verification: running backend/main.py with single SIGINT must exit cleanly with code 0 and no tracebacks."""
    from nyx.infrastructure.filesystem import REPO_ROOT
    repo_root = str(REPO_ROOT)
    cmd = [sys.executable, "-m", "backend.main"]
    env = os.environ.copy()
    env["NYX_PORT"] = "8977"
    env["PYTHONPATH"] = repo_root

    proc = subprocess.Popen(
        cmd,
        cwd=repo_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    # Wait until Uvicorn has finished startup and is actively serving
    start_time = time.time()
    startup_output = []
    while time.time() - start_time < 10:
        line = proc.stdout.readline()
        startup_output.append(line)
        if "Uvicorn running on" in line:
            break
    time.sleep(0.5)

    proc.send_signal(signal.SIGINT)
    stdout, _ = proc.communicate(timeout=10)
    full_output = "".join(startup_output) + stdout

    assert proc.returncode == 0
    assert "Traceback" not in full_output
    assert "CancelledError" not in full_output
    assert "Force exit requested by operator" not in full_output
    assert "NYX Web Platform shutdown complete." in full_output


def test_live_backend_main_double_sigint_force_exit():
    """Live verification: sending double SIGINT to backend/main.py must force-exit with code 130."""
    from nyx.infrastructure.filesystem import REPO_ROOT
    repo_root = str(REPO_ROOT)
    cmd = [sys.executable, "-m", "backend.main"]
    env = os.environ.copy()
    env["NYX_PORT"] = "8978"
    env["PYTHONPATH"] = repo_root

    proc = subprocess.Popen(
        cmd,
        cwd=repo_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    start_time = time.time()
    startup_output = []
    while time.time() - start_time < 10:
        line = proc.stdout.readline()
        startup_output.append(line)
        if "Uvicorn running on" in line:
            break
    time.sleep(0.5)

    proc.send_signal(signal.SIGINT)
    time.sleep(0.01)
    proc.send_signal(signal.SIGINT)
    stdout, _ = proc.communicate(timeout=5)
    full_output = "".join(startup_output) + stdout

    assert proc.returncode == 130
    assert "Force exit requested by operator (Ctrl+C x2)" in full_output
