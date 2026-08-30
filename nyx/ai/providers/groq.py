"""
NYX Groq Provider Integration
Integrates Groq using the openai Python SDK with bounded timeouts,
daemon thread wall-clock ceiling, and strict error classification.
"""
from __future__ import annotations

import os
import json
import time
import logging
import threading
from typing import Any, Dict, List, Optional
from nyx.ai.base import AIProvider

logger = logging.getLogger(__name__)

try:
    from groq import Groq
    HAS_GROQ_NATIVE_SDK = True
except ImportError:
    Groq = None  # type: ignore
    HAS_GROQ_NATIVE_SDK = False

try:
    import openai
    HAS_OPENAI_SDK = True
except ImportError:
    openai = None  # type: ignore
    HAS_OPENAI_SDK = False

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

HAS_GROQ_SDK = HAS_GROQ_NATIVE_SDK or HAS_OPENAI_SDK


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


def _classify_groq_error(ex: Exception) -> Dict[str, Any]:
    """Classify and normalize Groq SDK exceptions into clean user-facing error structures with full details."""
    if ex is None:
        return {"status": "error", "message": "Unknown error", "details": "", "status_code": None}

    status_code = getattr(ex, "status_code", None)
    if status_code is None and hasattr(ex, "response") and ex.response is not None:
        status_code = getattr(ex.response, "status_code", None)
    if status_code is None and hasattr(ex, "code") and isinstance(getattr(ex, "code"), int):
        status_code = getattr(ex, "code")

    err_str = _sanitize_error(str(ex))
    err_lower = err_str.lower()
    code_tag = f" [HTTP {status_code}]" if status_code else ""

    if "timeout" in err_lower or "timed out" in err_lower:
        return {
            "status": "error",
            "error_type": "timeout",
            "message": f"Groq API connection timed out{code_tag}: {err_str}",
            "details": err_str,
            "status_code": status_code,
        }

    if any(k in err_lower for k in ["500", "502", "503", "504", "service unavailable", "bad gateway"]):
        return {
            "status": "service_unavailable",
            "error_type": "service_unavailable",
            "message": f"Groq service temporarily unavailable{code_tag}: {err_str}",
            "details": "The selected Groq model is currently overloaded. Retry later.",
            "status_code": status_code,
        }

    if any(k in err_lower for k in ["quota", "rate limit", "429", "too many requests"]):
        return {
            "status": "error",
            "error_type": "rate_limit",
            "message": f"Groq API rate limit/quota reached{code_tag}: {err_str}",
            "details": err_str,
            "status_code": status_code,
        }

    if any(k in err_lower for k in ["api_key_invalid", "unauthenticated", "401", "403", "invalid api key"]):
        return {
            "status": "error",
            "error_type": "auth_error",
            "message": f"Groq API authentication failed{code_tag}: {err_str}",
            "details": err_str,
            "status_code": status_code,
        }

    if any(k in err_lower for k in ["connect", "ssl", "handshake", "getaddrinfo", "connection refused", "socket", "network is unreachable"]):
        return {
            "status": "error",
            "error_type": "connection_error",
            "message": f"Unable to connect to Groq API{code_tag}: {err_str}",
            "details": err_str,
            "status_code": status_code,
        }

    return {
        "status": "error",
        "error_type": "request_error",
        "message": f"Groq API request failed{code_tag}: {err_str}",
        "details": err_str,
        "status_code": status_code,
    }


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
            return None, "groq or openai Python SDK is not installed (pip install groq or pip install openai)"

        key = self.api_key or os.environ.get("GROQ_API_KEY")
        if not key:
            return None, "GROQ_API_KEY environment variable is not configured in the current process environment"

        try:
            http_client = None
            if httpx is not None:
                timeout_cfg = httpx.Timeout(self.timeout_ms / 1000.0)
                # Force IPv4 socket binding to prevent WSL2 IPv6 connection delays/stalls
                transport = httpx.HTTPTransport(local_address="0.0.0.0")
                http_client = httpx.Client(timeout=timeout_cfg, transport=transport)

            if HAS_GROQ_NATIVE_SDK and Groq is not None:
                if http_client is not None:
                    client = Groq(api_key=key, http_client=http_client, max_retries=0)
                else:
                    client = Groq(api_key=key, timeout=self.timeout_ms / 1000.0, max_retries=0)
                return client, None
            elif HAS_OPENAI_SDK and openai is not None:
                if http_client is not None:
                    client = openai.OpenAI(
                        api_key=key,
                        base_url="https://api.groq.com/openai/v1",
                        http_client=http_client,
                        max_retries=0,
                    )
                else:
                    client = openai.OpenAI(
                        api_key=key,
                        base_url="https://api.groq.com/openai/v1",
                        timeout=self.timeout_ms / 1000.0,
                        max_retries=0,
                    )
                return client, None
            else:
                return None, "groq or openai Python SDK is not installed"
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
                    {"role": "user", "content": "Say OK if you can read this."}
                ],
                max_completion_tokens=512,
            )
            choice = response.choices[0] if response.choices else None
            if not choice:
                raise ValueError("Groq API returned empty choices list in completion response")
            msg = choice.message
            content = getattr(msg, "content", None) or getattr(msg, "reasoning", None) or ""
            if not content.strip():
                finish_reason = getattr(choice, "finish_reason", "unknown")
                raise ValueError(
                    f"Groq model returned empty content (finish_reason: {finish_reason}, "
                    f"tokens exhausted by reasoning or model generated no text)"
                )
            return content

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
            code_str = f" [HTTP {err_dict['status_code']}]" if err_dict.get("status_code") else ""
            logger.error(
                "Groq API error [%s%s]: %s",
                err_dict.get("status", "error"),
                code_str,
                err_dict.get("message", str(ex)),
            )
            return err_dict

    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        client, err = self._get_client()
        if not client:
            raise ValueError(f"Groq provider not initialized: {err}")

        opts = options or {}
        max_tokens = opts.get("max_tokens") or opts.get("max_completion_tokens") or 1024

        def _do_generate():
            kwargs: Dict[str, Any] = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt}],
                "max_completion_tokens": max_tokens,
            }
            if "temperature" in opts:
                kwargs["temperature"] = opts["temperature"]
            try:
                response = client.chat.completions.create(**kwargs)
            except Exception as e:
                err_msg = str(e).lower()
                if "max_completion_tokens" in err_msg or "unrecognized" in err_msg or "extra_forbidden" in err_msg:
                    kwargs.pop("max_completion_tokens", None)
                    kwargs["max_tokens"] = max_tokens
                    response = client.chat.completions.create(**kwargs)
                else:
                    raise

            choice = response.choices[0] if response.choices else None
            if not choice:
                raise ValueError("Groq API returned empty choices list in completion response")
            msg = choice.message
            content = getattr(msg, "content", None) or getattr(msg, "reasoning", None) or ""
            if not content.strip():
                finish_reason = getattr(choice, "finish_reason", "unknown")
                raise ValueError(
                    f"Groq model returned empty content (finish_reason: {finish_reason}, "
                    f"tokens exhausted by reasoning or model generated no text)"
                )
            return content

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
            code_str = f" [HTTP {err_dict['status_code']}]" if err_dict.get("status_code") else ""
            logger.error(
                "Groq API error [%s%s]: %s",
                err_dict.get("status", "error"),
                code_str,
                err_dict.get("message", str(ex)),
            )
            raise RuntimeError(f"Groq API Error ({err_dict.get('status', 'error')}{code_str}): {err_dict.get('message', str(ex))}")

    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None) -> Dict[str, Any]:
        """Perform security context analysis using Groq."""
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

        try:
            generated = self.generate(custom_prompt)
        except Exception as ex:
            generated = str(ex)

        # Parse JSON output
        focus, reasoning = None, None
        data: Optional[Dict[str, Any]] = None
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
                    f_val = data.get("focus") or data.get("decision") or data.get("recommended_focus")
                    r_val = data.get("reasoning") or data.get("analysis") or clean_text
                    if f_val:
                        focus = str(f_val).strip()
                        reasoning = str(r_val or "").strip()
            except Exception:
                pass

        if focus or (isinstance(data, dict) and ("selected_index" in data or "decision" in data)):
            res_dict = {
                "provider": self.provider_name,
                "model": self.model_name,
                "target": target,
                "analysis": reasoning or generated,
                "recommended_focus": focus or "AI decision",
            }
            if isinstance(data, dict):
                res_dict.update(data)
            return res_dict

        # Fallback when JSON parsing fails or call failed
        error_msg = str(generated).strip()
        if "Groq API Error:" in error_msg:
            error_msg = error_msg.replace("Groq API Error:", "").strip()
        elif "Groq provider not initialized:" in error_msg:
            error_msg = error_msg.replace("Groq provider not initialized:", "").strip()
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
        if not options:
            return {"action": "none", "reason": "No options provided."}
        chosen = options[0]
        return {
            "provider": self.provider_name,
            "decision": chosen.get("action", "unknown"),
            "option": chosen,
            "confidence": 0.90,
        }
