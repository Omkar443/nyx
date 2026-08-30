"""
Unit tests for real-time terminal observability, subprocess tracking, and clean shutdown.
"""
import asyncio
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from nyx.infrastructure.logging import setup_logging, get_logger, NYXLogFormatter
from nyx.infrastructure.process import (
    register_process,
    unregister_process,
    terminate_all_subprocesses,
    _active_processes,
)
from nyx.execution.timeout import run_with_timeout
from nyx.web.app import create_app


def test_logging_configuration():
    """Verify logger setup, formatter, and hierarchy."""
    setup_logging()
    logger = get_logger("test_module")
    assert logger.name == "nyx.test_module"
    assert logger.isEnabledFor(20)  # INFO level enabled


def test_realtime_streaming_and_process_tracking(tmp_path: Path):
    """Verify run_with_timeout tracks process and returns stdout/stderr cleanly."""
    cmd = [sys.executable, "-c", "import sys; print('Line 1'); print('Line 2'); print('Error line', file=sys.stderr)"]
    code, stdout, stderr, timed_out = run_with_timeout(cmd, timeout_sec=5)
    assert code == 0
    assert not timed_out
    assert "Line 1" in stdout
    assert "Line 2" in stdout
    assert "Error line" in stderr


def test_terminate_all_subprocesses_kills_orphans():
    """Verify terminate_all_subprocesses immediately terminates tracked processes."""
    # Spawn a sleeping background process
    cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
    proc = subprocess.Popen(cmd)
    register_process(proc)
    assert proc.poll() is None
    assert proc in _active_processes

    # Terminate all
    terminate_all_subprocesses()
    time.sleep(0.2)
    assert proc.poll() is not None
    assert len(_active_processes) == 0


def test_server_lifespan_startup_and_clean_shutdown():
    """Verify FastAPI server initializes cleanly and shuts down without hanging."""
    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json().get("status") in ("ok", "healthy")
    # When exiting the context manager, lifespan teardown runs and completes immediately
