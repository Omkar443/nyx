"""
NYX Infrastructure Command Execution Engine
"""
from __future__ import annotations

import atexit
import os
import signal
import subprocess
import sys
import threading
from typing import Set

from nyx.infrastructure.tools import get_cmd_path
from nyx.infrastructure.logging import get_logger

logger = get_logger("nyx.process")

_active_processes: Set[subprocess.Popen] = set()
_lock = threading.Lock()


def register_process(proc: subprocess.Popen) -> None:
    """Register an active subprocess for lifecycle and signal termination tracking."""
    with _lock:
        _active_processes.add(proc)


def unregister_process(proc: subprocess.Popen) -> None:
    """Deregister a finished subprocess from active tracking."""
    with _lock:
        _active_processes.discard(proc)


def terminate_all_subprocesses() -> None:
    """Terminate and kill all registered child subprocesses to guarantee zero orphaned processes."""
    with _lock:
        procs = list(_active_processes)
        _active_processes.clear()

    if not procs:
        return

    logger.info("[SHUTDOWN] Terminating %d active child subprocess(es)...", len(procs))

    for proc in procs:
        try:
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass

    # Brief grace period before SIGKILL
    for proc in procs:
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass


_is_shutting_down = False
_shutdown_lock = threading.Lock()


def setup_signal_handlers() -> None:
    """Install signal handlers for clean SIGINT / SIGTERM child process termination."""
    try:
        if threading.current_thread() is threading.main_thread():
            orig_sigint = signal.getsignal(signal.SIGINT)
            orig_sigterm = signal.getsignal(signal.SIGTERM)

            def _sigint_handler(sig, frame):
                global _is_shutting_down
                terminate_all_subprocesses()
                with _shutdown_lock:
                    if _is_shutting_down:
                        return
                    _is_shutting_down = True

                if callable(orig_sigint) and orig_sigint not in (signal.SIG_IGN, signal.SIG_DFL, _sigint_handler):
                    orig_sigint(sig, frame)
                else:
                    raise KeyboardInterrupt

            def _sigterm_handler(sig, frame):
                global _is_shutting_down
                terminate_all_subprocesses()
                with _shutdown_lock:
                    if _is_shutting_down:
                        return
                    _is_shutting_down = True

                if callable(orig_sigterm) and orig_sigterm not in (signal.SIG_IGN, signal.SIG_DFL, _sigterm_handler):
                    orig_sigterm(sig, frame)
                else:
                    sys.exit(0)

            signal.signal(signal.SIGINT, _sigint_handler)
            signal.signal(signal.SIGTERM, _sigterm_handler)
    except Exception:
        pass


# Ensure interpreter termination terminates all running security tools
atexit.register(terminate_all_subprocesses)
setup_signal_handlers()


def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Execute command safely with timeout, path resolution, and process tracking."""
    if not cmd:
        return 1, "", "empty command"
    resolved_bin = get_cmd_path(cmd[0])
    exec_cmd = [resolved_bin] + cmd[1:] if resolved_bin else cmd
    try:
        proc = subprocess.Popen(
            exec_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        register_process(proc)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return proc.returncode, stdout or "", stderr or ""
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return 124, stdout or "", "timeout"
        finally:
            unregister_process(proc)
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except Exception as e:
        return 1, "", str(e)

