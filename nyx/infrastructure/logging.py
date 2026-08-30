"""
NYX Centralized Logging Module
Provides uniform, human-readable terminal logging across all NYX backend components.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_INITIALIZED = False


class NYXLogFormatter(logging.Formatter):
    """Custom formatter with optional ANSI terminal color highlighting."""

    COLORS = {
        logging.DEBUG: "\033[36m",     # Cyan
        logging.INFO: "\033[32m",      # Green
        logging.WARNING: "\033[33m",   # Yellow
        logging.ERROR: "\033[31m",     # Red
        logging.CRITICAL: "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        if sys.stdout.isatty():
            color = self.COLORS.get(record.levelno, "")
            if color:
                level_str = f"[{record.levelname}]"
                colored_level = f"{color}{level_str}{self.RESET}"
                formatted = formatted.replace(level_str, colored_level, 1)
        return formatted


def setup_logging(level: Optional[int] = None) -> None:
    """Initialize NYX root logging configuration."""
    global _INITIALIZED
    if _INITIALIZED:
        return

    log_level_name = os.environ.get("NYX_LOG_LEVEL", "INFO").upper()
    resolved_level = level if level is not None else getattr(logging, log_level_name, logging.INFO)

    root_logger = logging.getLogger("nyx")
    root_logger.setLevel(resolved_level)

    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(resolved_level)
        formatter = NYXLogFormatter(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT)
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    root_logger.propagate = False
    _INITIALIZED = True


def get_logger(name: str = "nyx") -> logging.Logger:
    """Retrieve logger instance under nyx hierarchy, ensuring logging is configured."""
    if not _INITIALIZED:
        setup_logging()
    if not name.startswith("nyx"):
        name = f"nyx.{name}"
    return logging.getLogger(name)
