import os
import time
import pytest
from unittest.mock import patch, MagicMock

from nyx.ai.providers import get_provider_class
from nyx.ai.providers.groq import GroqProvider, _classify_groq_error
from nyx.ai.manager import AIManager

def test_groq_provider_resolution():
    """Test that 'groq' resolves to GroqProvider, and manager recognizes it."""
    cls = get_provider_class("groq")
    assert cls == GroqProvider
    
    manager = AIManager()
    manager.set_active_provider("groq")
    assert manager.active_provider_name == "groq"
    prov = manager.get_provider("groq")
    assert isinstance(prov, GroqProvider)

def test_groq_missing_credentials():
    with patch.dict(os.environ, clear=True):
        provider = GroqProvider()
        with patch("nyx.ai.providers.groq.HAS_GROQ_SDK", True):
            info = provider.get_info()
            assert info["status"] == "unavailable"
            assert info["configured"] is False
            
            res = provider.test_connection()
            assert res["success"] is False
            assert res["status"] == "unavailable"

def test_groq_missing_sdk():
    with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
        provider = GroqProvider()
        with patch("nyx.ai.providers.groq.HAS_GROQ_SDK", False):
            info = provider.get_info()
            assert info["status"] == "error"
            assert info["configured"] is True
            assert "Python SDK is not installed" in info["error"]

def test_classify_groq_error():
    assert _classify_groq_error(Exception("Connection timed out"))["status"] == "error"
    assert _classify_groq_error(Exception("503 Service Unavailable"))["status"] == "service_unavailable"
    assert _classify_groq_error(Exception("429 too many requests"))["status"] == "error"

@patch("nyx.ai.providers.groq.HAS_GROQ_SDK", True)
def test_groq_successful_generation():
    with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
        provider = GroqProvider(model_name="llama-3.3-70b-versatile")
        
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Hello Groq"
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response
        
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client
        mock_httpx = MagicMock()
        
        with patch("nyx.ai.providers.groq.openai", mock_openai_module), patch("nyx.ai.providers.groq.httpx", mock_httpx):
            res = provider.generate("Hi")
            assert res == "Hello Groq"
            mock_client.chat.completions.create.assert_called_once()
            args, kwargs = mock_client.chat.completions.create.call_args
            assert kwargs["model"] == "llama-3.3-70b-versatile"
            assert kwargs["messages"][0]["content"] == "Hi"

@patch("nyx.ai.providers.groq.HAS_GROQ_SDK", True)
def test_groq_timeout():
    with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
        timeout_sec = 0.5
        provider = GroqProvider(total_timeout_sec=timeout_sec)
        
        mock_client = MagicMock()
        def slow_call(*args, **kwargs):
            time.sleep(2.0)
            return MagicMock()
            
        mock_client.chat.completions.create.side_effect = slow_call
        
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client
        mock_httpx = MagicMock()
        
        start_time = time.time()
        with patch("nyx.ai.providers.groq.openai", mock_openai_module), patch("nyx.ai.providers.groq.httpx", mock_httpx):
            with pytest.raises(RuntimeError) as exc:
                provider.generate("Hi")
            assert "timed out" in str(exc.value)
        elapsed = time.time() - start_time
        assert elapsed < 1.0

@patch("nyx.ai.providers.groq.HAS_GROQ_SDK", True)
def test_groq_auth_failure():
    with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
        provider = GroqProvider()
        
        mock_client = MagicMock()
        def auth_error(*args, **kwargs):
            raise Exception("api_key_invalid")
            
        mock_client.chat.completions.create.side_effect = auth_error
        
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client
        mock_httpx = MagicMock()
        
        with patch("nyx.ai.providers.groq.openai", mock_openai_module), patch("nyx.ai.providers.groq.httpx", mock_httpx):
            with pytest.raises(RuntimeError) as exc:
                provider.generate("Hi")
            assert "authentication failed" in str(exc.value)

@patch("nyx.ai.providers.groq.HAS_GROQ_SDK", True)
def test_groq_network_failure():
    with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_key"}):
        provider = GroqProvider()
        
        mock_client = MagicMock()
        def network_error(*args, **kwargs):
            raise Exception("network is unreachable")
            
        mock_client.chat.completions.create.side_effect = network_error
        
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client
        mock_httpx = MagicMock()
        
        with patch("nyx.ai.providers.groq.openai", mock_openai_module), patch("nyx.ai.providers.groq.httpx", mock_httpx):
            with pytest.raises(RuntimeError) as exc:
                provider.generate("Hi")
            assert "Unable to connect" in str(exc.value)
