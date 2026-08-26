import os
import time
import pytest
from unittest.mock import patch, MagicMock

from nyx.ai.providers import get_provider_class
from nyx.ai.providers.grok import GrokProvider, _classify_xai_error
from nyx.ai.manager import AIManager

def test_provider_resolution():
    """Test that 'grok' resolves to GrokProvider, and manager recognizes it."""
    cls = get_provider_class("grok")
    assert cls == GrokProvider
    
    manager = AIManager()
    manager.set_active_provider("grok")
    assert manager.active_provider_name == "grok"
    prov = manager.get_provider("grok")
    assert isinstance(prov, GrokProvider)

def test_grok_missing_credentials():
    with patch.dict(os.environ, clear=True):
        provider = GrokProvider()
        # Mock HAS_XAI_SDK just in case it's true
        with patch("nyx.ai.providers.grok.HAS_XAI_SDK", True):
            info = provider.get_info()
            assert info["status"] == "unavailable"
            assert info["configured"] is False
            
            res = provider.test_connection()
            assert res["success"] is False
            assert res["status"] == "unavailable"

def test_grok_missing_sdk():
    with patch.dict(os.environ, {"XAI_API_KEY": "test_key"}):
        provider = GrokProvider()
        with patch("nyx.ai.providers.grok.HAS_XAI_SDK", False):
            info = provider.get_info()
            assert info["status"] == "error"
            assert info["configured"] is True
            assert "Python SDK is not installed" in info["error"]

def test_classify_xai_error():
    assert _classify_xai_error(Exception("Connection timed out"))["status"] == "timeout"
    assert _classify_xai_error(Exception("503 Service Unavailable"))["status"] == "service_unavailable"
    assert _classify_xai_error(Exception("429 too many requests"))["status"] == "quota_exceeded"
    # Zero credits / permission denied
    res_cred = _classify_xai_error(Exception("403 permission-denied: team doesn't have any credits"))
    assert res_cred["status"] == "zero_credits"
    assert "no credits" in res_cred["message"]
    # Invalid key
    res_key = _classify_xai_error(Exception("401 invalid_api_key"))
    assert res_key["status"] == "auth_failed"
    assert "Invalid XAI_API_KEY" in res_key["message"]

@patch("nyx.ai.providers.grok.HAS_XAI_SDK", True)
def test_grok_successful_generation():
    with patch.dict(os.environ, {"XAI_API_KEY": "test_key"}):
        provider = GrokProvider(model_name="grok-2-latest")
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Hello Grok"
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response
        
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client
        mock_httpx = MagicMock()
        
        with patch("nyx.ai.providers.grok.openai", mock_openai_module), patch("nyx.ai.providers.grok.httpx", mock_httpx):
            res = provider.generate("Hi")
            assert res == "Hello Grok"
            mock_client.chat.completions.create.assert_called_once()
            args, kwargs = mock_client.chat.completions.create.call_args
            assert kwargs["model"] == "grok-2-latest"
            assert kwargs["messages"][0]["content"] == "Hi"

@patch("nyx.ai.providers.grok.HAS_XAI_SDK", True)
def test_grok_timeout():
    with patch.dict(os.environ, {"XAI_API_KEY": "test_key"}):
        timeout_sec = 0.5
        provider = GrokProvider(total_timeout_sec=timeout_sec)
        
        mock_client = MagicMock()
        def slow_call(*args, **kwargs):
            time.sleep(2.0)
            return MagicMock()
            
        mock_client.chat.completions.create.side_effect = slow_call
        
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client
        mock_httpx = MagicMock()
        
        start_time = time.time()
        with patch("nyx.ai.providers.grok.openai", mock_openai_module), patch("nyx.ai.providers.grok.httpx", mock_httpx):
            with pytest.raises(RuntimeError) as exc:
                provider.generate("Hi")
            assert "timed out" in str(exc.value)
        elapsed = time.time() - start_time
        # Should return within timeout_sec limit (+ a small margin for processing overhead)
        assert elapsed < 1.0

@patch("nyx.ai.providers.grok.HAS_XAI_SDK", True)
def test_grok_auth_failure():
    with patch.dict(os.environ, {"XAI_API_KEY": "test_key"}):
        provider = GrokProvider()
        
        mock_client = MagicMock()
        def auth_error(*args, **kwargs):
            raise Exception("api_key_invalid")
            
        mock_client.chat.completions.create.side_effect = auth_error
        
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client
        mock_httpx = MagicMock()
        
        with patch("nyx.ai.providers.grok.openai", mock_openai_module), patch("nyx.ai.providers.grok.httpx", mock_httpx):
            with pytest.raises(RuntimeError) as exc:
                provider.generate("Hi")
            assert "Invalid XAI_API_KEY" in str(exc.value) or "auth" in str(exc.value).lower()

@patch("nyx.ai.providers.grok.HAS_XAI_SDK", True)
def test_grok_network_failure():
    with patch.dict(os.environ, {"XAI_API_KEY": "test_key"}):
        provider = GrokProvider()
        
        mock_client = MagicMock()
        def network_error(*args, **kwargs):
            raise Exception("network is unreachable")
            
        mock_client.chat.completions.create.side_effect = network_error
        
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client
        mock_httpx = MagicMock()
        
        with patch("nyx.ai.providers.grok.openai", mock_openai_module), patch("nyx.ai.providers.grok.httpx", mock_httpx):
            with pytest.raises(RuntimeError) as exc:
                provider.generate("Hi")
            assert "Unable to connect" in str(exc.value)
