"""
Unit tests for AnalysisService.rank_surface() and core surface ranking logic.
"""
from __future__ import annotations

import json
import pytest
from pathlib import Path
from nyx.application.analysis_service import AnalysisService
from nyx.core.analysis import score_endpoint, rank_surface


def test_score_endpoint_priorities():
    # High priority API & Auth
    api_score, api_reason = score_endpoint("https://example.com/api/v1/users?id=1")
    assert api_score >= 80
    assert "API" in api_reason or "User-controlled" in api_reason

    auth_score, auth_reason = score_endpoint("https://example.com/oauth/authorize")
    assert auth_score >= 80
    assert "Authentication" in auth_reason

    # Low priority static assets
    css_score, css_reason = score_endpoint("https://example.com/static/style.css")
    assert css_score == 10
    assert "Static asset" in css_reason


def test_rank_surface_valid_manifest(tmp_path):
    manifest_data = {
        "target": "testtarget.com",
        "hosts": [
            {"url": "https://testtarget.com/static/logo.png"},
            {"url": "https://testtarget.com/api/v1/auth/login"},
            {"url": "https://testtarget.com/admin/dashboard"}
        ],
        "subdomains": ["api.testtarget.com"]
    }
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    service = AnalysisService()
    res = service.rank_surface("testtarget.com", manifest=str(manifest_file))

    assert res.get("status") == "success"
    assert res.get("target") == "testtarget.com"
    rankings = res.get("rankings", [])
    assert len(rankings) == 4

    # Highest score should be api/admin endpoints over static logo.png
    scores = [item["score"] for item in rankings]
    assert scores == sorted(scores, reverse=True)
    assert rankings[-1]["endpoint"] == "https://testtarget.com/static/logo.png"
    assert rankings[-1]["score"] == 10


def test_rank_surface_empty_manifest(tmp_path):
    manifest_data = {"target": "emptytarget.com", "hosts": [], "subdomains": []}
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    service = AnalysisService()
    res = service.rank_surface("emptytarget.com", manifest=str(manifest_file))

    assert res.get("status") == "success"
    assert res.get("rankings") == []


def test_rank_surface_missing_manifest():
    service = AnalysisService()
    res = service.rank_surface("nonexistenttarget12345.org", manifest="invalid/path/manifest.json")

    assert res.get("status") == "error"
    assert "No recon manifest" in res.get("message", "") or "Could not parse" in res.get("message", "")
