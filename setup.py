#!/usr/bin/env python3
"""
NYX Security Intelligence Engine — Setup & Installation Entry Point
Run 'python3 setup.py' to launch the interactive onboarding wizard,
or standard 'pip install -e .' / 'python3 setup.py install' for package installation.
"""
import sys
from pathlib import Path

SETUP_ARGS = {"build", "install", "develop", "sdist", "bdist_wheel", "egg_info", "--help-commands"}

if __name__ == "__main__" and (len(sys.argv) == 1 or not any(arg in SETUP_ARGS for arg in sys.argv[1:])):
    try:
        from nyx.setup_wizard import main
        main()
        sys.exit(0)
    except ImportError:
        pass

# Standard setuptools configuration fallback
try:
    from setuptools import setup, find_packages
    setup(
        name="nyx-security-engine",
        version="1.0.0",
        description="NYX Security Intelligence Engine",
        packages=find_packages(),
        entry_points={
            "console_scripts": [
                "nyx=nyx_cli.cli:main",
            ],
        },
    )
except Exception:
    pass
