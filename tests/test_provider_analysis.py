import json
import os
from unittest.mock import MagicMock, patch
import pytest

from nyx.ai.providers.gemini import GeminiProvider
from nyx.ai.providers.openai import OpenAIProvider
from nyx.ai.providers.local import LocalLLMProvider
from nyx.ai.providers.claude import ClaudeProvider
from nyx.ai.providers.grok import GrokProvider
from nyx.ai.planner import MissionPlanner


def test_gemini_analyze_valid_json():
    prov = GeminiProvider()
    valid_json_response = json.dumps({
        "focus": "PHP Remote File Inclusion & SQLi",
        "reasoning": "Target exposes PHP backend with 77 endpoints. Mutillidae stack suggests high likelihood of SQLi and LFI."
    })
    
    with patch.object(prov, "generate", return_value=valid_json_response):
        ctx = {
            "target": "server.vulnapp.id",
            "technologies": ["PHP", "nginx", "MySQL"],
            "endpoints": ["/mutillidae/index.php", "/mutillidae/login.php"],
            "phase": "ANALYSIS",
        }
        res = prov.analyze(ctx)
        assert res["recommended_focus"] == "PHP Remote File Inclusion & SQLi"
        assert "Mutillidae stack" in res["analysis"]
        assert res["provider"] == "gemini"


def test_gemini_analyze_markdown_wrapped_json():
    prov = GeminiProvider()
    wrapped_json = "```json\n" + json.dumps({
        "focus": "OAuth & Token Validation",
        "reasoning": "Identified OAuth authorization endpoints and bearer tokens."
    }) + "\n```"

    with patch.object(prov, "generate", return_value=wrapped_json):
        ctx = {"target": "oauth.example.com", "technologies": ["OAuth2"], "endpoints": ["/oauth/token"]}
        res = prov.analyze(ctx)
        assert res["recommended_focus"] == "OAuth & Token Validation"
        assert "Identified OAuth" in res["analysis"]


def test_gemini_analyze_failure_fallback():
    prov = GeminiProvider()
    with patch.object(prov, "generate", return_value="[Gemini Provider Error]: Gemini API connection timed out"):
        ctx = {"target": "server.vulnapp.id"}
        res = prov.analyze(ctx)
        assert res["recommended_focus"] == "AI analysis unavailable"
        assert "Gemini API connection timed out" in res["analysis"]


def test_gemini_analyze_invalid_json_fallback():
    prov = GeminiProvider()
    with patch.object(prov, "generate", return_value="Here is my security analysis without JSON formatting"):
        ctx = {"target": "server.vulnapp.id"}
        res = prov.analyze(ctx)
        assert res["recommended_focus"] == "AI analysis unavailable"
        assert "Here is my security analysis" in res["analysis"]


def test_openai_analyze_valid_json():
    prov = OpenAIProvider()
    valid_json = json.dumps({
        "focus": "GraphQL Batching & Auth Bypass",
        "reasoning": "Target runs Apollo GraphQL with exposed introspection query endpoints."
    })
    with patch.object(prov, "generate", return_value=valid_json):
        ctx = {"target": "api.example.com", "technologies": ["GraphQL", "Node.js"]}
        res = prov.analyze(ctx)
        assert res["recommended_focus"] == "GraphQL Batching & Auth Bypass"
        assert "Apollo GraphQL" in res["analysis"]


def test_openai_analyze_failure_fallback():
    prov = OpenAIProvider()
    with patch.object(prov, "generate", side_effect=RuntimeError("OpenAI API Error: OpenAI API connection timed out")):
        ctx = {"target": "api.example.com"}
        res = prov.analyze(ctx)
        assert res["recommended_focus"] == "AI analysis unavailable"
        assert "OpenAI API connection timed out" in res["analysis"]


def test_local_provider_context_aware_focus_varies():
    prov = LocalLLMProvider()

    # 1. PHP stack
    ctx_php = {
        "target": "server.vulnapp.id",
        "technologies": ["PHP", "nginx"],
        "endpoints": ["/index.php?page=view", "/login.php"],
    }
    res_php = prov.analyze(ctx_php)
    assert res_php["recommended_focus"] == "PHP & Web Server Attack Surface Analysis"
    assert "PHP" in res_php["analysis"]

    # 2. ASP.NET stack
    ctx_asp = {
        "target": "corporate.example.com",
        "technologies": ["ASP.NET", "IIS"],
        "endpoints": ["/search.aspx"],
    }
    res_asp = prov.analyze(ctx_asp)
    assert res_asp["recommended_focus"] == "ASP.NET & IIS Configuration Testing"
    assert "ASP.NET/IIS" in res_asp["analysis"]

    # 3. Node.js stack
    ctx_node = {
        "target": "spa.example.com",
        "technologies": ["Node.js", "Express", "React"],
        "endpoints": ["/api/v1/users"],
    }
    res_node = prov.analyze(ctx_node)
    assert res_node["recommended_focus"] == "Node.js & JavaScript API Security"
    assert "JavaScript/Node.js" in res_node["analysis"]

    # 4. Java / Spring stack
    ctx_java = {
        "target": "enterprise.example.com",
        "technologies": ["Spring Boot", "Java"],
        "endpoints": ["/actuator/health"],
    }
    res_java = prov.analyze(ctx_java)
    assert res_java["recommended_focus"] == "Java & Spring Framework Vulnerability Testing"
    assert "Java/Spring" in res_java["analysis"]

    # Assert outputs are distinct (not hardcoded)
    focus_set = {res_php["recommended_focus"], res_asp["recommended_focus"], res_node["recommended_focus"], res_java["recommended_focus"]}
    assert len(focus_set) == 4


def test_claude_analyze_valid_json():
    prov = ClaudeProvider()
    valid_json = json.dumps({
        "focus": "Broken Object Level Authorization (BOLA)",
        "reasoning": "Target exposes REST API routes with numeric object IDs and lacks centralized authorization middleware."
    })
    with patch.object(prov, "generate", return_value=valid_json):
        ctx = {
            "target": "api.cloudcorp.io",
            "technologies": ["FastAPI", "PostgreSQL"],
            "endpoints": ["/api/v2/tenants/10/users/42"],
            "phase": "ANALYSIS",
        }
        res = prov.analyze(ctx)
        assert res["provider"] == "claude"
        assert res["recommended_focus"] == "Broken Object Level Authorization (BOLA)"
        assert "numeric object IDs" in res["analysis"]


def test_claude_analyze_markdown_wrapped_json():
    prov = ClaudeProvider()
    wrapped_json = "```json\n" + json.dumps({
        "focus": "SAML XML Signature Wrapping",
        "reasoning": "Target relies on SAML SSO endpoint without strict signature verification."
    }) + "\n```"

    with patch.object(prov, "generate", return_value=wrapped_json):
        ctx = {"target": "sso.example.com", "technologies": ["SAML 2.0"], "endpoints": ["/saml/sso"]}
        res = prov.analyze(ctx)
        assert res["recommended_focus"] == "SAML XML Signature Wrapping"
        assert "SAML SSO" in res["analysis"]


def test_claude_analyze_failure_fallback():
    prov = ClaudeProvider()
    with patch.object(prov, "generate", side_effect=RuntimeError("Claude API Error: Claude API connection timed out")):
        ctx = {"target": "api.example.com"}
        res = prov.analyze(ctx)
        assert res["provider"] == "claude"
        assert res["recommended_focus"] == "AI analysis unavailable"
        assert "Claude API connection timed out" in res["analysis"]


def test_claude_analyze_invalid_json_fallback():
    prov = ClaudeProvider()
    with patch.object(prov, "generate", return_value="Unstructured text analysis without JSON formatting"):
        ctx = {"target": "api.example.com"}
        res = prov.analyze(ctx)
        assert res["provider"] == "claude"
        assert res["recommended_focus"] == "AI analysis unavailable"
        assert "Unstructured text analysis" in res["analysis"]


def test_grok_default_model_is_grok_4_6():
    with patch.dict(os.environ, {}, clear=True):
        prov = GrokProvider()
        assert prov.model_name == "grok-4.6"

