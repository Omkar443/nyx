"""
NYX Timeout & Subprocess Execution Layer
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

from nyx.infrastructure.logging import get_logger
from nyx.infrastructure.process import register_process, unregister_process

logger = get_logger("nyx.execution")


def run_with_timeout(
    cmd_list: list[str],
    timeout_sec: int = 60,
    cwd: Path | str | None = None,
    env: dict | None = None,
    stream_output: bool = True,
) -> tuple[int, str, str, bool]:
    """Execute command vector in a controlled subprocess with strict timeout enforcement
    and real-time line-by-line stdout/stderr streaming.
    Returns (exit_code, stdout, stderr, timed_out)."""
    env_vars = env or os.environ.copy()

    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=cwd,
            env=env_vars,
        )
    except FileNotFoundError as e:
        tool_bin = cmd_list[0] if cmd_list else "unknown"
        return 127, "", f"[PROCESS NOT STARTED] Executable '{tool_bin}' not found on system path: {e}", False
    except Exception as e:
        return 1, "", f"[EXECUTION ERROR] {e}", False

    register_process(proc)

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []

    def _read_stdout():
        try:
            if proc.stdout:
                for line in iter(proc.stdout.readline, ""):
                    if not line:
                        break
                    stdout_lines.append(line)
                    stripped = line.rstrip("\r\n")
                    if stream_output and stripped:
                        logger.info("[EXEC] %s", stripped)
        except Exception:
            pass
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass

    def _read_stderr():
        try:
            if proc.stderr:
                for line in iter(proc.stderr.readline, ""):
                    if not line:
                        break
                    stderr_lines.append(line)
                    stripped = line.rstrip("\r\n")
                    if stream_output and stripped:
                        logger.warning("[EXEC:stderr] %s", stripped)
        except Exception:
            pass
        finally:
            try:
                if proc.stderr:
                    proc.stderr.close()
            except Exception:
                pass

    t_out = threading.Thread(target=_read_stdout, daemon=True)
    t_err = threading.Thread(target=_read_stderr, daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        start_t = time.time()
        while proc.poll() is None:
            if time.time() - start_t > timeout_sec:
                timed_out = True
                proc.kill()
                break
            time.sleep(0.05)

        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)
        exit_code = proc.poll() if proc.poll() is not None else (-1 if timed_out else 0)
    except BaseException:
        try:
            proc.kill()
        except Exception:
            pass
        unregister_process(proc)
        raise
    finally:
        unregister_process(proc)

    full_stdout = "".join(stdout_lines)
    full_stderr = "".join(stderr_lines)
    if timed_out:
        full_stderr = (full_stderr + f"\nCommand execution timed out after {timeout_sec} seconds.").strip()

    return exit_code, full_stdout, full_stderr, timed_out

