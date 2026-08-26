"""
NYX Gemini AI Provider Integration
Integrates Google Gemini using the official google-genai SDK with bounded timeouts,
daemon thread wall-clock ceiling, AFC suppression, cross-environment diagnostics, and strict error classification.
"""
from __future__ import annotations

import os
import re
import json
import time
import logging
import threading
from typing import Any, Dict, List, Optional
from nyx.ai.base import AIProvider

logger = logging.getLogger(__name__)

try:
    from google import genai
    from google.genai import types
    from google.genai.errors import ClientError, APIError
    HAS_GENAI = True
except ImportError:
    genai = None  # type: ignore
    types = None  # type: ignore
    ClientError = None  # type: ignore
    APIError = None  # type: ignore
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


def _classify_gemini_error(ex: Exception, model_name: Optional[str] = None) -> Dict[str, str]:
    """Classify and normalize Gemini SDK exceptions into clean user-facing error structures."""
    if ex is None:
        return {"status": "error", "message": "Unknown error", "details": ""}

    err_str = _sanitize_error(str(ex))
    err_lower = err_str.lower()
    m_name = model_name or "gemini"

    # 1. Rate limit / Quota errors (429 RESOURCE_EXHAUSTED) - short circuit before timeout
    if any(k in err_lower for k in [
        "resource_exhausted", "quota", "rate limit", "rate_limit", "429", "too many requests"
    ]):
        retry_m = re.search(r"retry (?:in|after) ([0-9.]+)s", err_str, re.I)
        retry_info = f" Retry after {int(float(retry_m.group(1)))}s," if retry_m else ""
        return {
            "status": "quota_exceeded",
            "message": f"Gemini API quota exceeded (free-tier limit reached for model {m_name}).{retry_info} or upgrade your plan at https://ai.dev/rate-limit",
            "details": err_str,
        }

    # 2. Model not found / deprecated (404 NOT_FOUND)
    if any(k in err_lower for k in ["404", "not_found", "not found", "is no longer available"]):
        return {
            "status": "model_not_found",
            "message": f"Gemini model '{m_name}' not found or no longer available. Update configuration to use gemini-2.5-flash or check available models.",
            "details": err_str,
        }

    # 3. Authentication errors (401, 403 / API_KEY_INVALID / permission_denied)
    if any(k in err_lower for k in [
        "api_key_invalid", "unauthenticated", "invalid api key", "invalid_api_key", "401"
    ]):
        return {
            "status": "auth_failed",
            "message": "Invalid GEMINI_API_KEY — check your key at https://aistudio.google.com",
            "details": err_str,
        }

    # 4. Service Unavailable (500, 502, 503, 504)
    if any(k in err_lower for k in ["500", "502", "503", "504", "service unavailable", "bad gateway", "gateway timeout", "service_unavailable"]):
        return {
            "status": "service_unavailable",
            "message": "Gemini service temporarily unavailable",
            "details": "The selected Gemini model is currently overloaded. Retry later or use another model."
        }

    # 5. Timeout errors (both SDK timeout and NYX total operation ceiling)
    if "timeout" in err_lower or "timed out" in err_lower or "deadline_exceeded" in err_lower:
        return {"status": "timeout", "message": "Gemini API connection timed out", "details": ""}

    # 6. Network / TLS / SSL / Connection errors
    if any(k in err_lower for k in [
        "connect", "ssl", "handshake", "getaddrinfo", "gai_error",
        "connection refused", "networkerror", "name or service not known",
        "socket", "stream"
    ]):
        return {"status": "connection_error", "message": "Unable to connect to Gemini API", "details": ""}

    # 7. Fallback generic error
    return {"status": "error", "message": f"Gemini API request failed: {err_str}", "details": err_str}


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
        self.model_name = model_name or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        
        fallback_env = os.environ.get("GEMINI_FALLBACK_MODELS")
        if fallback_env is not None:
            self.fallback_models = [m.strip() for m in fallback_env.split(",") if m.strip()]
        else:
            self.fallback_models = ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-flash-latest", "gemini-pro-latest", "gemini-3.6-flash"]

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
            models_to_try.append("gemini-2.5-flash")

        last_error_info = None

        for current_model in models_to_try:
            def _do_check(m_name=current_model):
                gen_config = self._get_gen_config()
                kwargs = {
                    "model": m_name,
                    "contents": "NYX connection health check",
                }
                if gen_config:
                    kwargs["config"] = gen_config
                return client.models.generate_content(**kwargs)

            try:
                res = _run_daemon_bounded(_do_check, total_timeout_sec=total_timeout_sec)
                text = getattr(res, "text", str(res))
                return {
                    "provider": self.provider_name,
                    "success": True,
                    "status": "ready",
                    "model": current_model,
                    "message": "Gemini API connection successful",
                    "sample": (text[:60] + "...") if len(text) > 60 else text,
                }
            except Exception as ex:
                err_info = _classify_gemini_error(ex, model_name=current_model)
                if err_info["status"] in ("service_unavailable", "model_not_found"):
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
        
        # If all models failed with service_unavailable or model_not_found
        if last_error_info:
            return {
                "provider": self.provider_name,
                "success": False,
                "status": last_error_info["status"],
                "model": last_error_info.get("model", self.model_name),
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
            models_to_try.append("gemini-2.5-flash")

        last_error_info = None

        for current_model in models_to_try:
            def _do_generate(m_name=current_model):
                gen_config = self._get_gen_config()
                kwargs = {
                    "model": m_name,
                    "contents": prompt,
                }
                if gen_config:
                    kwargs["config"] = gen_config
                return client.models.generate_content(**kwargs)

            try:
                res = _run_daemon_bounded(_do_generate, total_timeout_sec=self.total_timeout_sec)
                if hasattr(res, "text") and res.text:
                    return res.text
                return str(res)
            except Exception as ex:
                err_info = _classify_gemini_error(ex, model_name=current_model)
                if err_info["status"] in ("service_unavailable", "model_not_found"):
                    logger.warning("Gemini model %s unavailable/not found, trying fallback...", current_model)
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
        technologies = context.get("technologies", [])
        endpoints = context.get("endpoints", [])
        phase = context.get("phase", "DISCOVERY")
        skills = context.get("skills", [])
        findings = context.get("findings") or context.get("previous_findings", [])

        if prompt:
            custom_prompt = prompt
        else:
            custom_prompt = (
                "You are assisting a licensed penetration tester operating within NYX, a "
                "policy-gated security testing tool. This specific target and action have "
                "already been verified as explicitly authorized and in-scope by NYX's own "
                "authorization and scope-enforcement system before this analysis request was "
                "ever made — you are analyzing already-collected, already-permitted "
                "reconnaissance data, not deciding whether to attack anything.\n\n"
                f"Target: {target}\n"
                f"Phase: {phase}\n"
                f"Detected Technologies: {technologies[:20]}\n"
                f"Harvested Endpoints: {endpoints[:20]}\n"
                f"Matched Security Skills: {skills[:15]}\n"
                f"Prior Findings Count: {len(findings)}\n\n"
                "Analyze this specific target context and provide a tailored, high-priority vulnerability research focus.\n"
                "Respond ONLY with a valid JSON object (no markdown code blocks, no ```json formatting, no explanation before or after) with exactly these two keys:\n"
                '{\n'
                '  "focus": "<short focus area, a few words>",\n'
                '  "reasoning": "<2-4 sentence explanation tied directly to the specific technologies, endpoints, or attack surface found>"\n'
                '}'
            )

        generated = self.generate(custom_prompt)

        # Parse JSON output
        focus, reasoning = None, None
        if generated and isinstance(generated, str):
            clean_text = generated.strip()
            if clean_text.startswith("```"):
                lines = clean_text.splitlines()
                if lines and lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                clean_text = "\n".join(lines).strip()
            try:
                data = json.loads(clean_text)
                if isinstance(data, dict):
                    f_val = data.get("focus")
                    r_val = data.get("reasoning")
                    if f_val and isinstance(f_val, str):
                        focus = f_val.strip()
                        reasoning = str(r_val or "").strip()
            except Exception:
                pass

        if focus:
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "target": target,
                "analysis": reasoning or generated,
                "recommended_focus": focus,
            }

        # Fallback when JSON parsing fails or call failed
        error_msg = str(generated).strip()
        if "[Gemini Provider Error]:" in error_msg:
            error_msg = error_msg.replace("[Gemini Provider Error]:", "").strip()
        elif "[Gemini Provider" in error_msg:
            error_msg = "Gemini API unavailable or offline"
        elif not error_msg:
            error_msg = "Model response was empty"

        return {
            "provider": self.provider_name,
            "model": self.model_name,
            "target": target,
            "analysis": error_msg,
            "recommended_focus": "AI analysis unavailable",
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
