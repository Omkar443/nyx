"""
NYX Interface Output Presentation Helpers
"""
from __future__ import annotations
import sys


def color(s: str, c: str) -> str:
    """Apply ANSI color codes if stdout is an interactive terminal."""
    if not sys.stdout.isatty():
        return s
    codes = {
        "red": 31,
        "green": 32,
        "yellow": 33,
        "blue": 34,
        "cyan": 36,
        "bold": 1,
        "dim": 2,
    }
    return f"\033[{codes.get(c, 0)}m{s}\033[0m"


def say(s: str = "") -> None:
    """Print output safely handling unicode encoding boundaries."""
    try:
        print(s)
    except UnicodeEncodeError:
        try:
            encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
            print(s.encode(encoding, errors="replace").decode(encoding))
        except Exception:
            print(s.encode("ascii", errors="replace").decode("ascii"))


def section(title: str) -> None:
    """Display formatted section header."""
    say()
    say(color("=" * 70, "blue"))
    say(color(title, "bold"))
    say(color("=" * 70, "blue"))
