"""
NYX Gemini AI Provider Hardened Integration & Daemon Total Operation Ceiling Test Suite
"""
import os
import sys
import time
from unittest.mock import patch, MagicMock
import pytest

from nyx.ai.base import AIProvider
from nyx.ai.providers import get_provider_class, GeminiProvider
from nyx.ai.providers.gemini import _classify_gemini_error, _sanitize_error, _run_daemon_bounded
from nyx.ai.manager import AIManager
from nyx.application.ai_service import AIService
from nyx.agent.agent import NYXAgent
from nyx.infrastructure.environment import PlatformInfo


def test_gemini_provider_registration():
    """Test 1: Gemini appears in provider registry and factory."""
    cls = get_provider_class("gemini")
    assert cls == GeminiProvider
    assert issubclass(cls, AIProvider)


def test_gemini_key_present_in_current_process():
    """Test 2: Gemini detects GEMINI_API_KEY present in current process and never leaks it."""
    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyTestSecretKey12345"}, clear=False):
        prov = GeminiProvider()
        info = prov.get_info()

        assert info["name"] == "gemini"
        assert info["configured"] is True
        assert info["model"] == "gemini-3.6-flash"
        info_str = str(info)
        assert "AIzaSyTestSecretKey12345" not in info_str


def test_gemini_key_absent_from_current_process():
    """Test 3: Gemini provider reports unavailable when GEMINI_API_KEY is absent from current process."""
    with patch.dict(os.environ, {}, clear=True):
        prov = GeminiProvider(api_key=None)
        info = prov.get_info()

        assert info["configured"] is False
        assert info["status"] == "unavailable"
        assert "not configured in the current process environment" in info["error"]


def test_gemini_immediate_return_when_key_missing():
    """Test 4: test_connection() immediately returns unavailable without making any network request when key is missing."""
    mock_genai = MagicMock()
    with patch.dict(os.environ, {}, clear=True), \
         patch("nyx.ai.providers.gemini.genai", mock_genai), \
         patch("nyx.ai.providers.gemini.HAS_GENAI", True):

        prov = GeminiProvider(api_key=None)
        res = prov.test_connection()

        assert res["success"] is False
        assert res["status"] == "unavailable"
        assert res["message"] == "GEMINI_API_KEY is not configured in the current process environment."
        mock_genai.Client.assert_not_called()


def test_platform_environment_detection():
    """Test 5: PlatformInfo environment detection for Windows, Linux, and WSL2."""
    with patch("sys.platform", "win32"):
        assert PlatformInfo.get_os() == "windows"
        assert PlatformInfo.is_wsl2() is False

    with patch("sys.platform", "darwin"):
        assert PlatformInfo.get_os() == "darwin"

    with patch("sys.platform", "linux"):
        with patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="Linux version 5.15.153.1-microsoft-standard-WSL2"):
            assert PlatformInfo.get_os() == "wsl2"
            assert PlatformInfo.is_wsl2() is True


def test_gemini_model_configuration():
    """Test 6: Gemini model is configurable via GEMINI_MODEL env var or constructor."""
    with patch.dict(os.environ, {"GEMINI_MODEL": "gemini-3.6-pro"}, clear=False):
        prov = GeminiProvider()
        assert prov.model_name == "gemini-3.6-pro"

    prov_custom = GeminiProvider(model_name="gemini-2.0-flash")
    assert prov_custom.model_name == "gemini-2.0-flash"


def test_existing_success_path_still_works():
    """Test 7: Existing success generation path works cleanly with mocked Client."""
    mock_genai = MagicMock()
    mock_client = MagicMock()
    mock_res = MagicMock()
    mock_res.output_text = "Analysis result: Potential SQL Injection identified in query param 'id'."
    mock_client.interactions.create.return_value = mock_res
    mock_genai.Client.return_value = mock_client

    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyMockKey"}, clear=False), \
         patch("nyx.ai.providers.gemini.genai", mock_genai), \
         patch("nyx.ai.providers.gemini.HAS_GENAI", True):

        prov = GeminiProvider()
        res = prov.generate("Analyze input params")

        assert "Potential SQL Injection" in res
        mock_client.interactions.create.assert_called_once()


def test_http_options_and_retry_options_configured():
    """Test 8: Verify HttpOptions(timeout=15000, retry_options=attempts=1) is configured."""
    mock_genai = MagicMock()
    mock_types = MagicMock()
    mock_client = MagicMock()
    mock_genai.Client.return_value = mock_client

    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyMockKey"}, clear=False), \
         patch("nyx.ai.providers.gemini.genai", mock_genai), \
         patch("nyx.ai.providers.gemini.types", mock_types), \
         patch("nyx.ai.providers.gemini.HAS_GENAI", True):

        prov = GeminiProvider(timeout_ms=15000)
        prov._get_client()

        mock_types.HttpRetryOptions.assert_called_once_with(attempts=1)
        mock_types.HttpOptions.assert_called_once()


def test_blocking_operation_returns_immediately_after_total_timeout():
    """Test 9: PROVE TIMING — Daemon thread ceiling returns in ~0.2s when operation sleeps for 60s."""
    def _60s_sleep():
        time.sleep(60.0)

    start = time.time()
    with pytest.raises(TimeoutError) as excinfo:
        _run_daemon_bounded(_60s_sleep, total_timeout_sec=0.2)
    elapsed = time.time() - start

    assert elapsed < 1.0
    assert "timed out after 0.2 seconds" in str(excinfo.value)


def test_windows_style_timeout_behavior():
    """Test 10: Windows-style socket/stream hang returns structured timeout error from test_connection()."""
    mock_genai = MagicMock()
    mock_client = MagicMock()
    mock_client.interactions.create.side_effect = TimeoutError("httpx.ReadTimeout: _network_stream.read timed out")
    mock_genai.Client.return_value = mock_client

    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyMockKey"}, clear=False), \
         patch("nyx.ai.providers.gemini.genai", mock_genai), \
         patch("nyx.ai.providers.gemini.HAS_GENAI", True):

        prov = GeminiProvider()
        res = prov.test_connection(total_timeout_sec=1.0)

        assert res["success"] is False
        assert res["status"] == "error"
        assert res["message"] == "Gemini API connection timed out"


def test_error_classifications_all_types():
    """Test 11: Comprehensive classification for TLS, network, 401, 429, 500, 503 errors."""
    # 401 / 403
    assert _classify_gemini_error(Exception("401 Client Error: API_KEY_INVALID"))["message"] == "Gemini API authentication failed"
    assert _classify_gemini_error(Exception("403 Forbidden: Permission denied"))["message"] == "Gemini API authentication failed"

    # 429
    assert _classify_gemini_error(Exception("429 RESOURCE_EXHAUSTED: Rate limit exceeded"))["message"] == "Gemini API rate limit/quota reached"

    # 500 / 503
    assert _classify_gemini_error(Exception("503 Service Unavailable: High load"))["message"] == "Gemini service temporarily unavailable"
    assert _classify_gemini_error(Exception("500 Internal Server Error"))["message"] == "Gemini service temporarily unavailable"

    # TLS / SSL / Network
    assert _classify_gemini_error(Exception("ssl.SSLError: [SSL: HANDSHAKE_FAILURE] handshake failed"))["message"] == "Unable to connect to Gemini API"
    assert _classify_gemini_error(Exception("getaddrinfo failed: name or service not known"))["message"] == "Unable to connect to Gemini API"

    # Timeout
    assert _classify_gemini_error(Exception("httpx.ConnectTimeout: Connection timed out"))["message"] == "Gemini API connection timed out"


def test_api_key_never_leaks_in_exception_or_sanitization():
    """Test 12: Sanitize error strips any secret key from tracebacks and exception output."""
    secret = "AIzaSySensitiveSecretKey9999"
    with patch.dict(os.environ, {"GEMINI_API_KEY": secret}, clear=False):
        raw_err = f"Error in request to https://generativelanguage.googleapis.com?key={secret}"
        clean = _sanitize_error(raw_err)

        assert secret not in clean
        assert "[REDACTED]" in clean


def test_ai_manager_gemini_integration():
    """Test 13: AIManager manages Gemini alongside existing providers."""
    mgr = AIManager(default_provider="gemini")
    assert mgr.active_provider_name == "gemini"

    prov = mgr.get_provider("gemini")
    assert isinstance(prov, GeminiProvider)

    providers = mgr.list_providers()
    p_names = [p["name"] for p in providers]
    assert "gemini" in p_names
    assert "claude" in p_names
    assert "openai" in p_names
    assert "local" in p_names


def test_ai_service_gemini_integration():
    """Test 14: AIService lists and tests Gemini correctly."""
    service = AIService()
    res = service.list_providers()
    assert res.is_success is True

    providers = res.data["providers"]
    gemini_info = next((p for p in providers if p["name"] == "gemini"), None)
    assert gemini_info is not None
    assert gemini_info["model"] in ("gemini-3.6-flash", "gemini-3.6-pro", "gemini-2.0-flash")


def test_agent_uses_nyx_ai_abstraction_not_direct_sdk():
    """Test 15: NYXAgent accesses Gemini via ReasoningEngine & AIManager, not direct SDK."""
    agent = NYXAgent(provider_name="gemini")
    assert agent.reasoning_engine.provider_name == "gemini"

    with patch.object(agent.reasoning_engine.ai_manager, "analyze", return_value={"analysis": "Mock analysis"}) as mock_analyze:
        res = agent.analyze()
        assert res["status"] == "completed"
        mock_analyze.assert_called_once()


def test_503_returns_service_unavailable():
    """Test 16: 503 returns service_unavailable status."""
    err = _classify_gemini_error(Exception("503 Service Unavailable"))
    assert err["status"] == "service_unavailable"
    assert err["message"] == "Gemini service temporarily unavailable"
    assert "overloaded" in err["details"]


def test_503_triggers_fallback():
    """Test 17: 503 triggers fallback to the next model in test_connection."""
    mock_genai = MagicMock()
    mock_client = MagicMock()
    # First call (primary) raises 503, second call (fallback) succeeds
    mock_client.interactions.create.side_effect = [
        Exception("503 Service Unavailable"),
        MagicMock(output_text="Fallback success")
    ]
    mock_genai.Client.return_value = mock_client

    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyMockKey", "GEMINI_MODEL": "gemini-3.6-flash", "GEMINI_FALLBACK_MODELS": "gemini-2.5-flash"}, clear=False), \
         patch("nyx.ai.providers.gemini.genai", mock_genai), \
         patch("nyx.ai.providers.gemini.HAS_GENAI", True):

        prov = GeminiProvider()
        res = prov.test_connection(total_timeout_sec=5.0)

        assert res["success"] is True
        assert res["model"] == "gemini-2.5-flash"
        assert res["sample"] == "Fallback success"
        assert mock_client.interactions.create.call_count == 2


def test_auth_error_does_not_fallback():
    """Test 18: 401 error does not trigger fallback and returns error."""
    mock_genai = MagicMock()
    mock_client = MagicMock()
    mock_client.interactions.create.side_effect = Exception("401 Unauthorized")
    mock_genai.Client.return_value = mock_client

    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyMockKey"}, clear=False), \
         patch("nyx.ai.providers.gemini.genai", mock_genai), \
         patch("nyx.ai.providers.gemini.HAS_GENAI", True):

        prov = GeminiProvider()
        res = prov.test_connection(total_timeout_sec=5.0)

        assert res["success"] is False
        assert res["status"] == "error"
        assert mock_client.interactions.create.call_count == 1


def test_quota_error_does_not_fallback():
    """Test 19: 429 quota error does not trigger fallback and returns error."""
    mock_genai = MagicMock()
    mock_client = MagicMock()
    mock_client.interactions.create.side_effect = Exception("429 Resource Exhausted")
    mock_genai.Client.return_value = mock_client

    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyMockKey"}, clear=False), \
         patch("nyx.ai.providers.gemini.genai", mock_genai), \
         patch("nyx.ai.providers.gemini.HAS_GENAI", True):

        prov = GeminiProvider()
        res = prov.test_connection(total_timeout_sec=5.0)

        assert res["success"] is False
        assert res["status"] == "error"
        assert mock_client.interactions.create.call_count == 1


def test_success_primary_model():
    """Test 20: Success on primary model does not trigger fallback."""
    mock_genai = MagicMock()
    mock_client = MagicMock()
    mock_client.interactions.create.return_value = MagicMock(output_text="Primary success")
    mock_genai.Client.return_value = mock_client

    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyMockKey", "GEMINI_MODEL": "gemini-3.6-flash", "GEMINI_FALLBACK_MODELS": "gemini-2.5-flash"}, clear=False), \
         patch("nyx.ai.providers.gemini.genai", mock_genai), \
         patch("nyx.ai.providers.gemini.HAS_GENAI", True):

        prov = GeminiProvider()
        res = prov.test_connection(total_timeout_sec=5.0)

        assert res["success"] is True
        assert res["model"] == "gemini-3.6-flash"
        assert mock_client.interactions.create.call_count == 1


def test_no_raw_google_error_leak():
    """Test 21: Raw Google JSON responses are not leaked."""
    mock_genai = MagicMock()
    mock_client = MagicMock()
    mock_client.interactions.create.side_effect = Exception('{"error": {"code": 503, "message": "The model is overloaded", "status": "UNAVAILABLE"}}')
    mock_genai.Client.return_value = mock_client

    with patch.dict(os.environ, {"GEMINI_API_KEY": "AIzaSyMockKey"}, clear=False), \
         patch("nyx.ai.providers.gemini.genai", mock_genai), \
         patch("nyx.ai.providers.gemini.HAS_GENAI", True):

        prov = GeminiProvider()
        res = prov.test_connection(total_timeout_sec=5.0)

        assert res["success"] is False
        assert "UNAVAILABLE" not in res["message"]
        assert "{" not in res["message"]
        assert res["status"] == "service_unavailable"
