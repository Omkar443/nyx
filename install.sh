#!/usr/bin/env bash
# =====================================================================
# NYX Security Intelligence Engine — Root Installation Script
# Launches the cross-platform setup & onboarding wizard.
# =====================================================================
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check for Python 3
if command -v python3 >/dev/null 2>&1; then
    PY_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PY_CMD="python"
else
    echo "[ERROR] Python 3.11+ is required to install NYX, but Python was not found in PATH."
    echo "Please install Python 3.11+ (https://www.python.org/downloads/) and rerun ./install.sh"
    exit 1
fi

exec "$PY_CMD" "$SCRIPT_DIR/setup.py" "$@"
