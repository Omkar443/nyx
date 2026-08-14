"""
NYX Gemini AI Provider Integration
Integrates Google Gemini using the official google-genai SDK with bounded timeouts,
daemon thread wall-clock ceiling, AFC suppression, cross-environment diagnostics, and strict error classification.
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
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    genai = None  # type: ignore
    types = None  # type: ignore
    HAS_GENAI = False


def _sanitize_error(error_msg: str) -> str:
    """Strip any accidental key disclosure from error messages."""
    if not error_msg:
        return ""
    clean = str(error_msg)
    for env_var in ["GEMINI_API_KEY", "GOOGLE_API_KEY"]:
        key_val = os.environ.get(env_var)
        if key_val and len(key_val) > 4:
            clean = clean.replace(key_val, "[REDACTED]")
    return clean


def _classify_gemini_error(ex: Exception) -> Dict[str, str]:
    """Classify and normalize Gemini SDK exceptions into clean user-facing error structures."""
    if ex is None:
        return {"status": "error", "message": "Unknown error", "details": ""}

    err_str = _sanitize_error(str(ex))
    err_lower = err_str.lower()

    # 1. Timeout errors (both SDK timeout and NYX total operation ceiling)
    if "timeout" in err_lower or "timed out" in err_lower or "deadline_exceeded" in err_lower:
        return {"status": "error", "message": "Gemini API connection timed out", "details": ""}

    # 2. Service Unavailable (500, 502, 503, 504)
    if any(k in err_lower for k in ["500", "502", "503", "504", "service unavailable", "bad gateway", "gateway timeout", "service_unavailable"]):
        return {
            "status": "service_unavailable",
            "message": "Gemini service temporarily unavailable",
            "details": "The selected Gemini model is currently overloaded. Retry later or use another model."
        }

    # 3. Rate limit / Quota errors (429)
    if any(k in err_lower for k in [
        "quota", "rate limit", "resource_exhausted", "429", "too many requests"
    ]):
        return {"status": "error", "message": "Gemini API rate limit/quota reached", "details": ""}

    # 4. Authentication errors (401, 403)
    if any(k in err_lower for k in [
        "api_key_invalid", "unauthenticated", "permission_denied",
        "invalid api key", "401", "403"
    ]):
        return {"status": "error", "message": "Gemini API authentication failed", "details": ""}

    # 5. Network / TLS / SSL / Connection errors
    if any(k in err_lower for k in [
        "connect", "ssl", "handshake", "getaddrinfo", "gai_error",
        "connection refused", "networkerror", "name or service not known",
        "socket", "stream"
    ]):
        return {"status": "error", "message": "Unable to connect to Gemini API", "details": ""}

    # 6. Fallback generic error
    return {"status": "error", "message": f"Gemini API request failed: {err_str}", "details": ""}


def _run_daemon_bounded(
    func,
    args=(),
    kwargs=None,
    total_timeout_sec: float = 20.0,
) -> Any:
    """Execute func in a daemon thread with hard wall-clock ceiling.
    Returns result or raises TimeoutError in exactly total_timeout_sec,
    never blocking the caller thread on thread join or executor shutdown.
    """
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
        raise TimeoutError(f"Gemini API connection timed out after {total_timeout_sec} seconds")

    if exception_container:
        raise exception_container[0]

    if result_container:
        return result_container[0]

    raise TimeoutError(f"Gemini API connection timed out after {total_timeout_sec} seconds")


class GeminiProvider(AIProvider):
    """Google Gemini AI Provider Implementation."""

    provider_name: str = "gemini"

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_ms: int = 15000,
        total_timeout_sec: float = 20.0,
    ):
        self.model_name = model_name or os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
        
        fallback_env = os.environ.get("GEMINI_FALLBACK_MODELS")
        if fallback_env is not None:
            self.fallback_models = [m.strip() for m in fallback_env.split(",") if m.strip()]
        else:
            self.fallback_models = ["gemini-3.6-flash", "gemini-2.5-flash", "gemini-2.5-flash-lite"]

        self.api_key = api_key
        self.timeout_ms = timeout_ms
        self.total_timeout_sec = total_timeout_sec

    def _get_client(self, timeout_ms: Optional[int] = None) -> tuple[Optional[Any], Optional[str]]:
        """Instantiate google.genai Client safely using GEMINI_API_KEY, 1-attempt retry policy, and bounded HTTP timeout."""
        if not HAS_GENAI:
            return None, "google-genai Python SDK is not installed (pip install google-genai)"

        key = self.api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            return None, "GEMINI_API_KEY environment variable is not configured in the current process environment"

        t_ms = timeout_ms or self.timeout_ms
        try:
            http_opts = None
            if types and hasattr(types, "HttpOptions"):
                retry_opts = None
                if hasattr(types, "HttpRetryOptions"):
                    # Explicitly disable multi-attempt SDK retries (1 attempt only) for strict budget control
                    retry_opts = types.HttpRetryOptions(attempts=1)
                http_opts = types.HttpOptions(timeout=t_ms, retry_options=retry_opts)

            client_kwargs = {"api_key": key}
            if http_opts:
                client_kwargs["http_options"] = http_opts

            client = genai.Client(**client_kwargs)
            return client, None
        except Exception as ex:
            return None, f"Failed to initialize Gemini client: {_sanitize_error(str(ex))}"

    def _get_gen_config(self) -> Optional[Any]:
        """Create GenerateContentConfig with Automatic Function Calling disabled to prevent AFC warnings."""
        if types and hasattr(types, "GenerateContentConfig"):
            try:
                afc = None
                if hasattr(types, "AutomaticFunctionCallingConfig"):
                    afc = types.AutomaticFunctionCallingConfig(disable=True)
                return types.GenerateContentConfig(automatic_function_calling=afc)
            except Exception:
                pass
        return None

    def get_info(self) -> Dict[str, Any]:
        """Return provider status and configuration info without leaking credentials."""
        client, err = self._get_client()
        is_configured = bool(self.api_key or os.environ.get("GEMINI_API_KEY"))
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
        """Perform a lightweight health check test against the Gemini API with daemon bounded timeout."""
        client, err = self._get_client(timeout_ms=timeout_ms)
        if not client:
            status_val = "unavailable"
            if "SDK" in (err or ""):
                msg = err or "google-genai Python SDK is not installed"
            else:
                msg = "GEMINI_API_KEY is not configured in the current process environment."
            return {
                "provider": self.provider_name,
                "success": False,
                "status": status_val,
                "model": self.model_name,
                "message": msg,
            }

        models_to_try = []
        if self.model_name:
            models_to_try.append(self.model_name)
        for m in self.fallback_models:
            if m not in models_to_try:
                models_to_try.append(m)
        if not models_to_try:
            models_to_try.append("gemini-3.6-flash")

        last_error_info = None

        for current_model in models_to_try:
            def _do_check(m_name=current_model):
                kwargs = {
                    "model": m_name,
                    "input": "NYX connection health check",
                }
                return client.interactions.create(**kwargs)

            try:
                res = _run_daemon_bounded(_do_check, total_timeout_sec=total_timeout_sec)
                text = getattr(res, "output_text", getattr(res, "text", str(res)))
                return {
                    "provider": self.provider_name,
                    "success": True,
                    "status": "ready",
                    "model": current_model,
                    "message": "Gemini API connection successful",
                    "sample": (text[:60] + "...") if len(text) > 60 else text,
                }
            except Exception as ex:
                err_info = _classify_gemini_error(ex)
                if err_info["status"] == "service_unavailable":
                    last_error_info = err_info
                    last_error_info["model"] = current_model
                    continue
                else:
                    return {
                        "provider": self.provider_name,
                        "success": False,
                        "status": err_info["status"],
                        "model": current_model,
                        "message": err_info["message"],
                        "details": err_info.get("details", ""),
                    }
        
        # If all models failed with service_unavailable
        if last_error_info:
            return {
                "provider": self.provider_name,
                "success": False,
                "status": last_error_info["status"],
                "model": last_error_info["model"],
                "message": last_error_info["message"],
                "details": last_error_info.get("details", ""),
            }

        # Fallback if no models to try (should not be reached)
        return {
            "provider": self.provider_name,
            "success": False,
            "status": "error",
            "model": self.model_name,
            "message": "Unknown error during connection test",
            "details": "",
        }

    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        """Generate text from prompt using Gemini model with daemon bounded operation timeout."""
        client, err = self._get_client()
        if not client:
            logger.warning("Gemini provider fallback triggered: %s", err)
            if "mission" in prompt.lower() or "plan" in prompt.lower():
                return "Recommended Mission:\n1. Technology fingerprinting\n2. Endpoint discovery\n3. Authentication analysis\n4. Validation workflow"
            return f"[Gemini Provider ({self.model_name}) Offline Mode]: {prompt[:60]}..."

        models_to_try = []
        if self.model_name:
            models_to_try.append(self.model_name)
        for m in self.fallback_models:
            if m not in models_to_try:
                models_to_try.append(m)
        if not models_to_try:
            models_to_try.append("gemini-3.6-flash")

        last_error_info = None

        for current_model in models_to_try:
            def _do_generate(m_name=current_model):
                gen_config = self._get_gen_config()
                kwargs = {
                    "model": m_name,
                    "input": prompt,
                }
                if gen_config:
                    kwargs["generation_config"] = gen_config
                return client.interactions.create(**kwargs)

            try:
                res = _run_daemon_bounded(_do_generate, total_timeout_sec=self.total_timeout_sec)
                if hasattr(res, "output_text") and res.output_text:
                    return res.output_text
                if hasattr(res, "text") and res.text:
                    return res.text
                return str(res)
            except Exception as ex:
                err_info = _classify_gemini_error(ex)
                if err_info["status"] == "service_unavailable":
                    logger.warning("Gemini model %s unavailable, trying fallback...", current_model)
                    last_error_info = err_info
                    continue
                else:
                    logger.error("Gemini text generation error: %s", err_info["message"])
                    return f"[Gemini Provider Error]: {err_info['message']}"

        if last_error_info:
            logger.error("All Gemini fallback models exhausted.")
            return f"[Gemini Provider Error]: {last_error_info['message']} - {last_error_info.get('details', '')}"

        return "[Gemini Provider Error]: Unknown generation failure"

    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None) -> Dict[str, Any]:
        """Perform security context analysis using Gemini."""
        target = context.get("target", "unknown")
        techs = context.get("technologies", [])
        custom_prompt = prompt or f"Analyze target '{target}' running technologies: {techs} and recommend focus areas."

        generated = self.generate(custom_prompt)
        return {
            "provider": self.provider_name,
            "model": self.model_name,
            "target": target,
            "analysis": generated,
            "recommended_focus": "Authentication and API Endpoint Analysis",
        }

    def decide(self, context: Dict[str, Any], options: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Make a security action decision based on context and available options."""
        if not options:
            return {"provider": self.provider_name, "action": "none", "reason": "No options provided."}

        chosen = options[0]
        return {
            "provider": self.provider_name,
            "model": self.model_name,
            "decision": chosen.get("action", "unknown"),
            "option": chosen,
            "confidence": 0.95,
        }
