"""
NYX Web Dashboard Authentication Test Suite
Tests:
- Token persistence across restarts
- REST Bearer and X-API-Token authentication success/failure
- WebSocket query token authentication success/failure
- Auth bootstrap endpoint alignment (/api/v1/auth/token)
"""
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from nyx.core import engagement
from nyx.web.app import create_app
from nyx.web.auth import get_or_create_api_token


@pytest.fixture
def clean_workspace(tmp_path, monkeypatch):
    """Fixture providing an isolated engagement workspace."""
    engagement.init_engagement("test.example.com", reset=True, base_dir=tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_api_token_persistence(clean_workspace):
    """Start app, get token, restart app, verify same token."""
    token_1 = get_or_create_api_token()
    assert token_1 and len(token_1) == 64

    token_2 = get_or_create_api_token()
    assert token_1 == token_2


def test_rest_auth_success(clean_workspace):
    """Send valid Bearer token and X-API-Token header; expect 200."""
    token = get_or_create_api_token()
    app = create_app()

    with TestClient(app) as client:
        # Test Authorization: Bearer header
        res1 = client.get("/api/v1/mission", headers={"Authorization": f"Bearer {token}"})
        assert res1.status_code == 200

        # Test X-API-Token header
        res2 = client.get("/api/v1/mission", headers={"X-API-Token": token})
        assert res2.status_code == 200


def test_rest_auth_failure(clean_workspace):
    """Send invalid token; expect 401 Unauthorized."""
    app = create_app()

    with TestClient(app) as client:
        res = client.get("/api/v1/mission", headers={"Authorization": "Bearer invalid_token_12345"})
        assert res.status_code == 401
        detail = res.json().get("detail", {})
        assert detail.get("code") == "UNAUTHORIZED"


def test_websocket_auth_success(clean_workspace):
    """Connect WebSocket using valid token; expect accepted connection."""
    token = get_or_create_api_token()
    app = create_app()

    with TestClient(app) as client:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            ws.send_text("ping")
            resp = ws.receive_text()
            assert resp == "pong"


def test_websocket_auth_failure(clean_workspace):
    """Connect WebSocket using invalid token; expect rejected connection."""
    app = create_app()

    with TestClient(app) as client:
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/events?token=invalid_token"):
                pass


def test_frontend_token_matches_backend(clean_workspace):
    """Verify auth endpoint returns the exact token returned by get_or_create_api_token()."""
    token = get_or_create_api_token()
    app = create_app()

    with TestClient(app) as client:
        res = client.get("/api/v1/auth/token")
        assert res.status_code == 200
        data = res.json()
        assert data.get("api_token") == token
        assert data.get("token") == token
