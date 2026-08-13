"""
NYX Backend Entry Point
Launches local FastAPI server via uvicorn.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import uvicorn
from nyx.web.auth import get_or_create_api_token


def main():
    host = os.environ.get("NYX_HOST", "127.0.0.1")
    port = int(os.environ.get("NYX_PORT", "8000"))
    token = get_or_create_api_token()

    print("=" * 60)
    print(" NYX Security Operations Dashboard")
    print("=" * 60)
    print(f" API Server:    http://{host}:{port}")
    print(f" Dashboard:     http://{host}:{port}")
    print(f" WebSocket:     ws://{host}:{port}/ws/events")
    print(f" API Docs:      http://{host}:{port}/api/docs")
    print(f" Authentication: ENABLED (Token configured)")
    print(f" API Token:     {token[:8]}...{token[-4:]}")
    print("=" * 60)

    uvicorn.run("nyx.web.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
