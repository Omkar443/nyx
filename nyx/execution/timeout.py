import json
import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

from nyx.infrastructure.logging import get_logger
from nyx.infrastructure.process import register_process, unregister_process

logger = get_logger("nyx.execution")

_ASCII_ART_CHARS = set("/\\_|-().[]#~%`=+:*^@$,;{}<>")
_BANNER_KEYWORDS = ("projectdiscovery.io", "nuclei.projectdiscovery.io", "ffuf.io", "sqlmap.org")


def _is_banner_or_noise(text: str) -> bool:
    """Detect ASCII art banners, watermarks, or decorative noise."""
    if not text:
        return True
    t_lower = text.lower()
    if any(k in t_lower for k in _BANNER_KEYWORDS):
        return True
    non_ws = [c for c in text if not c.isspace()]
    if non_ws:
        art_chars = [c for c in non_ws if c in _ASCII_ART_CHARS]
        if len(art_chars) / len(non_ws) >= 0.65:
            return True
    return False


def _format_stdout_line(line: str) -> str | None:
    """Format stdout line for human-readable terminal output without altering raw capture."""
    stripped = line.rstrip("\r\n")
    if not stripped:
        return None

    # Filter pure ASCII banner noise
    if _is_banner_or_noise(stripped):
        return None

    # Structured JSONL Summarization (e.g. Nuclei, FFuF, HTTPX)
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            data = json.loads(stripped)
            if not isinstance(data, dict):
                return stripped

            # Nuclei finding record
            if "template-id" in data or "templateID" in data or "info" in data:
                tid = data.get("template-id") or data.get("templateID") or "nuclei-finding"
                info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
                name = info.get("name") or tid
                sev = str(info.get("severity") or data.get("severity") or "info").upper()
                matched = data.get("matched-at") or data.get("matched") or data.get("host") or ""
                return f"Finding: {tid} [{sev}] ({name}) on {matched}"

            # FFuF result
            if "url" in data and "status" in data:
                return f"Discovered: {data.get('url')} [status: {data.get('status')}, size: {data.get('length')}]"

            # HTTPX result
            if "url" in data and "status_code" in data:
                title = data.get("title") or ""
                return f"Host: {data.get('url')} [{data.get('status_code')}] {title}".strip()

            # Generic JSON: fallback if short, or summarize if giant
            if len(stripped) > 160:
                keys = list(data.keys())[:5]
                return f"JSON result ({', '.join(keys)}...)"
        except Exception:
            pass

    return stripped


def _route_stderr_line(line: str) -> tuple[str | None, int]:
    """Determine log level and message for stderr lines without false warnings on banners/stats."""
    stripped = line.rstrip("\r\n")
    if not stripped:
        return None, logging.DEBUG

    # Suppress ASCII art banners and vendor watermarks
    if _is_banner_or_noise(stripped):
        return stripped, logging.DEBUG

    # Routine informational stats (Nuclei [INF], FFuF Progress, sqlmap startup info)
    if stripped.startswith(("[INF]", "[INFO]", "[*]", ":: Progress", ":: Job")):
        return stripped, logging.DEBUG

    # Genuine warnings and errors
    if any(k in stripped.lower() for k in ("error", "fatal", "fail", "exception", "refused", "timed out", "[err]", "[fatal]")):
        return stripped, logging.WARNING

    return stripped, logging.DEBUG


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
                    if stream_output:
                        formatted = _format_stdout_line(line)
                        if formatted:
                            logger.info("[EXEC] %s", formatted)
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
                    if stream_output:
                        msg, level = _route_stderr_line(line)
                        if msg:
                            if level >= logging.WARNING:
                                logger.warning("[EXEC:stderr] %s", msg)
                            elif level == logging.DEBUG:
                                logger.debug("[EXEC:stderr] %s", msg)
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
        last_heartbeat_t = start_t
        tool_name = cmd_list[0] if cmd_list else "command"
        if tool_name == "wsl" and len(cmd_list) > 1:
            tool_name = cmd_list[1]

        while proc.poll() is None:
            now = time.time()
            if now - start_t > timeout_sec:
                timed_out = True
                proc.kill()
                break
            if now - last_heartbeat_t >= 10.0:
                elapsed_sec = int(now - start_t)
                logger.info("[EXEC] Still running '%s'... (elapsed: %ds / timeout: %ds)", tool_name, elapsed_sec, int(timeout_sec))
                last_heartbeat_t = now
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

