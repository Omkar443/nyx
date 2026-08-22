"""
NYX Groq Provider Integration
Integrates Groq using the openai Python SDK with bounded timeouts,
daemon thread wall-clock ceiling, and strict error classification.
"""
from __future__ import annotations

import os
import time
import logging
import threading
from typing import Any, Dict, List, Optional
from nyx.ai.base import AIProvider

logger = logging.getLogger(__name__)

try:
    import openai
    import httpx
    HAS_GROQ_SDK = True
except ImportError:
    openai = None  # type: ignore
    httpx = None  # type: ignore
    HAS_GROQ_SDK = False


def _sanitize_error(error_msg: str) -> str:
    """Strip any accidental key disclosure from error messages."""
    if not error_msg:
        return ""
    clean = str(error_msg)
    for env_var in ["GROQ_API_KEY"]:
        key_val = os.environ.get(env_var)
        if key_val and len(key_val) > 4:
            clean = clean.replace(key_val, "[REDACTED]")
    return clean


def _classify_groq_error(ex: Exception) -> Dict[str, str]:
    """Classify and normalize Groq SDK exceptions into clean user-facing error structures."""
    if ex is None:
        return {"status": "error", "message": "Unknown error", "details": ""}

    err_str = _sanitize_error(str(ex))
    err_lower = err_str.lower()

    if "timeout" in err_lower or "timed out" in err_lower:
        return {"status": "error", "message": "Groq API connection timed out", "details": ""}

    if any(k in err_lower for k in ["500", "502", "503", "504", "service unavailable", "bad gateway"]):
        return {
            "status": "service_unavailable",
            "message": "Groq service temporarily unavailable",
            "details": "The selected Groq model is currently overloaded. Retry later."
        }

    if any(k in err_lower for k in ["quota", "rate limit", "429", "too many requests"]):
        return {"status": "error", "message": "Groq API rate limit/quota reached", "details": ""}

    if any(k in err_lower for k in ["api_key_invalid", "unauthenticated", "401", "403", "invalid api key"]):
        return {"status": "error", "message": "Groq API authentication failed", "details": ""}

    if any(k in err_lower for k in ["connect", "ssl", "handshake", "getaddrinfo", "connection refused", "socket", "network is unreachable"]):
        return {"status": "error", "message": "Unable to connect to Groq API", "details": ""}

    return {"status": "error", "message": f"Groq API request failed: {err_str}", "details": ""}


def _run_daemon_bounded(
    func,
    args=(),
    kwargs=None,
    total_timeout_sec: float = 20.0,
) -> Any:
    """Execute func in a daemon thread with hard wall-clock ceiling."""
    kwargs = kwargs or {}
    result_container = []
    exception_container = []

    def _worker():
        try:
            res = func(*args, **kwargs)
            result_container.append(res)
        except Exception as ex:
            exception_container.append(ex)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout=total_timeout_sec)

    if t.is_alive():
        raise TimeoutError(f"Groq API connection timed out after {total_timeout_sec} seconds")

    if exception_container:
        raise exception_container[0]

    if result_container:
        return result_container[0]

    raise TimeoutError(f"Groq API connection timed out after {total_timeout_sec} seconds")


class GroqProvider(AIProvider):
    """Groq AI Provider Implementation."""

    provider_name: str = "groq"

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_ms: int = 15000,
        total_timeout_sec: float = 20.0,
    ):
        self.model_name = model_name or os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.api_key = api_key
        self.timeout_ms = timeout_ms
        self.total_timeout_sec = total_timeout_sec

    def _get_client(self) -> tuple[Optional[Any], Optional[str]]:
        if not HAS_GROQ_SDK:
            return None, "openai Python SDK is not installed (pip install openai)"

        key = self.api_key or os.environ.get("GROQ_API_KEY")
        if not key:
            return None, "GROQ_API_KEY environment variable is not configured in the current process environment"

        try:
            timeout_cfg = httpx.Timeout(self.timeout_ms / 1000.0)
            client = openai.OpenAI(
                api_key=key,
                base_url="https://api.groq.com/openai/v1",
                timeout=timeout_cfg,
                max_retries=0  # Disable hidden SDK retries
            )
            return client, None
        except Exception as ex:
            return None, f"Failed to initialize Groq client: {_sanitize_error(str(ex))}"

    def get_info(self) -> Dict[str, Any]:
        """Return provider status and configuration info without leaking credentials."""
        client, err = self._get_client()
        is_configured = bool(self.api_key or os.environ.get("GROQ_API_KEY"))
        status = "ready" if (client and is_configured) else ("unavailable" if not is_configured else "error")

        return {
            "name": self.provider_name,
            "type": self.__class__.__name__,
            "status": status,
            "configured": is_configured,
            "model": self.model_name,
            "error": err,
        }

    def test_connection(self, timeout_ms: int = 15000, total_timeout_sec: float = 20.0) -> Dict[str, Any]:
        info = self.get_info()
        if info["status"] != "ready":
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "success": False,
                "status": info["status"],
                "message": info.get("error", "Not configured properly"),
            }

        client, err = self._get_client()
        if not client:
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "success": False,
                "status": "error",
                "message": str(err),
            }

        def _do_test():
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a test client."},
                    {"role": "user", "content": "Say OK if you can read this."}
                ],
                max_tokens=10,
            )
            return response.choices[0].message.content

        logger.info(f"Groq test_connection request started (model: {self.model_name})")
        try:
            text = _run_daemon_bounded(_do_test, total_timeout_sec=total_timeout_sec)
            logger.info("Groq response received successfully")
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "success": True,
                "status": "ready",
                "message": "Groq API connection successful",
            }
        except TimeoutError as ex:
            logger.error("Groq API connection timed out")
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "success": False,
                "status": "error",
                "message": "Groq API connection timed out",
            }
        except Exception as ex:
            err_dict = _classify_groq_error(ex)
            err_dict["provider"] = self.provider_name
            err_dict["model"] = self.model_name
            err_dict["success"] = False
            logger.error(f"Groq API error category: {err_dict['status']}")
            return err_dict

    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        client, err = self._get_client()
        if not client:
            raise ValueError(f"Groq provider not initialized: {err}")

        def _do_generate():
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.choices[0].message.content

        logger.info(f"Groq generate request started (model: {self.model_name})")
        try:
            res = _run_daemon_bounded(_do_generate, total_timeout_sec=self.total_timeout_sec)
            logger.info("Groq response received successfully")
            return res
        except TimeoutError as ex:
            logger.error("Groq API connection timed out")
            raise RuntimeError("Groq API Error: Groq API connection timed out")
        except Exception as ex:
            err_dict = _classify_groq_error(ex)
            logger.error(f"Groq API error category: {err_dict['status']}")
            raise RuntimeError(f"Groq API Error: {err_dict['message']} - {err_dict['details']}")

    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None) -> Dict[str, Any]:
        target = context.get("target", "unknown")
        findings = context.get("previous_findings", [])
        return {
            "provider": self.provider_name,
            "target": target,
            "analysis": f"Analyzed target '{target}' with {len(findings)} prior findings.",
            "recommended_focus": "Business Logic & Rate Limit Vulnerability Testing",
        }

    def decide(self, context: Dict[str, Any], options: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not options:
            return {"action": "none", "reason": "No options provided."}
        chosen = options[0]
        return {
            "provider": self.provider_name,
            "decision": chosen.get("action", "unknown"),
            "option": chosen,
            "confidence": 0.90,
        }
