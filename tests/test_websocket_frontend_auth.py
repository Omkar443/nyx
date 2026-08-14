"""
NYX WebSocket Frontend Authentication Regression Test Suite
Tests:
- Backend generated token equals WebSocket accepted token
- Old / invalid tokens are rejected with policy violation (1008 / 403)
- Fresh token connects successfully
- Token refresh reconnect logic
"""
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from nyx.core import engagement
from nyx.web.app import create_app
from nyx.web.auth import get_or_create_api_token, _CACHED_TOKEN


@pytest.fixture
def clean_workspace(tmp_path, monkeypatch):
    """Fixture providing an isolated engagement workspace."""
    engagement.init_engagement("test.example.com", reset=True, base_dir=tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_websocket_accepts_current_backend_token(clean_workspace):
    """Confirm backend generated token connects successfully to WebSocket."""
    token = get_or_create_api_token()
    assert token and len(token) == 64

    app = create_app()
    with TestClient(app) as client:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_text("ping")
            resp = ws.receive_text()
            assert resp == "pong"


def test_websocket_rejects_stale_or_invalid_token(clean_workspace):
    """Confirm old / invalid token is rejected by WebSocket with policy violation 1008."""
    app = create_app()
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws/events?token=old_stale_token_12345"):
                pass
        assert exc_info.value.code == 1008


def test_websocket_token_refresh_reconnect(clean_workspace, monkeypatch):
    """Confirm that when backend token changes, old token fails and new token connects successfully."""
    # Initial token
    token_old = get_or_create_api_token()
    app = create_app()

    with TestClient(app) as client:
        # Old token works initially
        with client.websocket_connect(f"/ws/events?token={token_old}") as ws:
            ws.send_text("ping")
            assert ws.receive_text() == "pong"

        # Simulate backend token update via environment variable override
        token_new = "new_fresh_token_abcdef1234567890abcdef1234567890"
        monkeypatch.setenv("NYX_API_TOKEN", token_new)

        # Old token must now be rejected
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(f"/ws/events?token={token_old}"):
                pass
        assert exc_info.value.code == 1008

        # New token must be accepted
        with client.websocket_connect(f"/ws/events?token={token_new}") as ws:
            ws.send_text("ping")
            assert ws.receive_text() == "pong"
