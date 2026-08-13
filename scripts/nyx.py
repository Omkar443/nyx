#!/usr/bin/env python3
"""Thin shim — run the NYX CLI from a clone without installing.

Kept for backward compatibility with `scripts/nyx.py <cmd>` and the existing
symlink instructions. The implementation now lives in `nyx_cli/cli.py`, which is also
the pip console-script entry point (`nyx`). See docs/nyx-cli.md.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nyx_cli.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
