import shutil
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from nyx.web.app import create_app
from nyx.web.auth import get_or_create_api_token
from nyx.core.skills import load_skills, list_skills
from nyx.infrastructure.filesystem import REPO_ROOT


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture
def auth_headers():
    token = get_or_create_api_token()
    return {
        "Authorization": f"Bearer {token}",
        "X-API-Token": token,
        "Content-Type": "application/json",
    }


def test_initial_skill_count_matches_core_discovery(client, auth_headers):
    """Verify backend API returns dynamic count matching core discovery."""
    core_skills = load_skills()
    initial_count = len(core_skills)
    assert initial_count >= 80

    # Check /api/v1/skills
    res = client.get("/api/v1/skills", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    api_count = data.get("data", {}).get("skill_count") or data.get("count")
    assert api_count == initial_count

    # Check /api/v1/skills/stats
    res_stats = client.get("/api/v1/skills/stats", headers=auth_headers)
    assert res_stats.status_code == 200
    stats_data = res_stats.json()
    assert stats_data.get("data", {}).get("skill_count") == initial_count


def test_dynamic_skill_addition_and_removal(client, auth_headers):
    """Verify adding/removing a valid SKILL.md dynamically updates count without code changes."""
    initial_skills = load_skills()
    initial_count = len(initial_skills)

    # 1. Create a dynamic test skill on disk
    test_skill_dir = REPO_ROOT / "skills" / "test-dynamic-live-skill-99"
    test_skill_dir.mkdir(parents=True, exist_ok=True)
    skill_file = test_skill_dir / "SKILL.md"
    skill_file.write_text(
        "---\n"
        "name: test-dynamic-live-skill-99\n"
        "description: Dynamic live skill validation module for testing.\n"
        "---\n\n"
        "# Dynamic Live Skill\n"
        "Validation test for live skill count.\n",
        encoding="utf-8"
    )

    try:
        # Verify core discovery incremented
        updated_skills = load_skills()
        assert len(updated_skills) == initial_count + 1
        assert "test-dynamic-live-skill-99" in updated_skills

        # Verify API /api/v1/skills returns incremented count
        res = client.get("/api/v1/skills", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data.get("data", {}).get("skill_count") == initial_count + 1

        # Verify API /api/v1/skills/stats returns incremented count
        res_stats = client.get("/api/v1/skills/stats", headers=auth_headers)
        assert res_stats.status_code == 200
        assert res_stats.json().get("data", {}).get("skill_count") == initial_count + 1

    finally:
        # Clean up test skill
        if test_skill_dir.exists():
            shutil.rmtree(test_skill_dir)

    # Verify count decremented back
    after_cleanup = load_skills()
    assert len(after_cleanup) == initial_count
    assert "test-dynamic-live-skill-99" not in after_cleanup

    res_after = client.get("/api/v1/skills/stats", headers=auth_headers)
    assert res_after.json().get("data", {}).get("skill_count") == initial_count


def test_invalid_files_not_counted_as_skills(client, auth_headers):
    """Verify non-skill files or folders without SKILL.md are ignored."""
    initial_count = len(load_skills())

    # Create dummy text files and folders
    dummy_dir = REPO_ROOT / "skills" / "not-a-skill-folder"
    dummy_dir.mkdir(parents=True, exist_ok=True)
    (dummy_dir / "random.txt").write_text("Not a skill file", encoding="utf-8")
    (dummy_dir / "README.md").write_text("# Not a skill", encoding="utf-8")

    try:
        current_skills = load_skills()
        assert len(current_skills) == initial_count

        res_stats = client.get("/api/v1/skills/stats", headers=auth_headers)
        assert res_stats.json().get("data", {}).get("skill_count") == initial_count
    finally:
        if dummy_dir.exists():
            shutil.rmtree(dummy_dir)


def test_duplicate_skill_registration_deduplicated(client, auth_headers):
    """Verify duplicate skill names across directories are deduplicated."""
    initial_skills = load_skills()
    initial_count = len(initial_skills)

    # Pick an existing skill name
    existing_name = list(initial_skills.keys())[0]

    # Create a duplicate in the other directory
    dup_dir = REPO_ROOT / "skills" / existing_name
    dup_dir.mkdir(parents=True, exist_ok=True)
    (dup_dir / "SKILL.md").write_text(
        f"---\nname: {existing_name}\ndescription: Duplicate entry\n---\n",
        encoding="utf-8"
    )

    try:
        dup_skills = load_skills()
        assert len(dup_skills) == initial_count
    finally:
        # Clean up only if we created it
        if dup_dir.exists() and (REPO_ROOT / ".agents" / "skills" / existing_name).exists():
            shutil.rmtree(dup_dir)


def test_health_check_returns_dynamic_skills_count(client):
    """Verify unauthenticated /health returns dynamic skills_count."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert "skills_count" in data
    assert isinstance(data["skills_count"], int)
    assert data["skills_count"] == len(load_skills())
