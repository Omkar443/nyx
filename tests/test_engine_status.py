"""
NYX Engine Status & Telemetry Regression Tests
Verifies the /api/v1/engine/status contract, categories mapping, tool diagnostics, and frontend safety invariants.
"""
from fastapi.testclient import TestClient
from nyx.web.app import create_app
from nyx.web.auth import get_or_create_api_token
from nyx.application.skill_service import SkillService


def test_engine_status_endpoint_contract():
    app = create_app()
    client = TestClient(app)
    token = get_or_create_api_token()

    # 1. Unauthenticated request should be rejected
    unauth_resp = client.get("/api/v1/engine/status")
    assert unauth_resp.status_code == 401

    # 2. Authenticated request should return full telemetry contract
    resp = client.get("/api/v1/engine/status", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    data = resp.json()

    assert data.get("success") is True
    payload = data.get("data", {})

    # Engine block
    engine = payload.get("engine", {})
    assert engine.get("name") == "NYX Security Intelligence Engine"
    assert engine.get("status") in ("HEALTHY", "ACTIVE", "READY")
    assert isinstance(engine.get("version"), str)
    assert isinstance(engine.get("target"), str)
    assert isinstance(engine.get("phase"), str)
    assert isinstance(engine.get("workspace_active"), bool)

    # Skills block
    skills = payload.get("skills", {})
    assert isinstance(skills.get("count"), int)
    assert skills.get("count") > 0
    categories = skills.get("categories")
    assert isinstance(categories, dict)
    assert len(categories) > 0
    for cat, count in categories.items():
        assert isinstance(cat, str)
        assert isinstance(count, int)
        assert count > 0

    # Tools block
    tools = payload.get("tools", {})
    assert isinstance(tools.get("available_count"), int)
    assert isinstance(tools.get("total_count"), int)
    tool_list = tools.get("list")
    assert isinstance(tool_list, list)
    assert len(tool_list) > 0
    for t in tool_list:
        assert "tool" in t
        assert "available" in t
        assert isinstance(t["available"], bool)

    # Vault block
    vault = payload.get("vault", {})
    assert isinstance(vault.get("mounted"), bool)
    assert isinstance(vault.get("findings_count"), int)
    assert isinstance(vault.get("evidence_count"), int)


def test_skill_service_categories_invariant():
    service = SkillService()
    res = service.get_skills_stats_result()
    assert res.is_success is True
    data = res.data
    assert isinstance(data.get("categories"), dict)
    assert data.get("count") == sum(data["categories"].values())
