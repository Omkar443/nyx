"""
NYX Anthropic Claude Provider Integration
Integrates Anthropic Claude using the official anthropic Python SDK with bounded timeouts,
daemon thread wall-clock ceiling, and strict error classification.
"""
from __future__ import annotations

import os
import json
import logging
import threading
from typing import Any, Dict, List, Optional
from nyx.ai.base import AIProvider

logger = logging.getLogger(__name__)

try:
    import anthropic
    HAS_ANTHROPIC_SDK = True
except ImportError:
    anthropic = None  # type: ignore
    HAS_ANTHROPIC_SDK = False


def _sanitize_error(error_msg: str) -> str:
    """Strip any accidental key disclosure from error messages."""
    if not error_msg:
        return ""
    clean = str(error_msg)
    for env_var in ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"]:
        key_val = os.environ.get(env_var)
        if key_val and len(key_val) > 4:
            clean = clean.replace(key_val, "[REDACTED]")
    return clean


def _classify_claude_error(ex: Exception) -> Dict[str, str]:
    """Classify and normalize Anthropic/Claude SDK exceptions into clean user-facing error structures."""
    if ex is None:
        return {"status": "error", "message": "Unknown error", "details": ""}

    err_str = _sanitize_error(str(ex))
    err_lower = err_str.lower()

    if "timeout" in err_lower or "timed out" in err_lower:
        return {"status": "error", "message": "Claude API connection timed out", "details": ""}

    if any(k in err_lower for k in ["500", "502", "503", "504", "service unavailable", "overloaded", "bad gateway"]):
        return {
            "status": "service_unavailable",
            "message": "Claude service temporarily unavailable",
            "details": "The selected Claude model is currently overloaded. Retry later."
        }

    if any(k in err_lower for k in ["quota", "rate limit", "429", "too many requests"]):
        return {"status": "error", "message": "Claude API rate limit/quota reached", "details": ""}

    if any(k in err_lower for k in ["api_key_invalid", "unauthenticated", "401", "403", "invalid api key", "authentication_error"]):
        return {"status": "error", "message": "Claude API authentication failed", "details": "Please check your ANTHROPIC_API_KEY environment variable."}

    if any(k in err_lower for k in ["connect", "ssl", "handshake", "getaddrinfo", "connection refused", "socket", "network is unreachable"]):
        return {"status": "error", "message": "Unable to connect to Claude API", "details": ""}

    return {"status": "error", "message": f"Claude API request failed: {err_str}", "details": ""}


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
        raise TimeoutError(f"Claude API connection timed out after {total_timeout_sec} seconds")

    if exception_container:
        raise exception_container[0]

    if result_container:
        return result_container[0]

    raise TimeoutError(f"Claude API connection timed out after {total_timeout_sec} seconds")


class ClaudeProvider(AIProvider):
    """Anthropic Claude AI Provider Implementation."""

    provider_name: str = "claude"

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_ms: int = 15000,
        total_timeout_sec: float = 20.0,
    ):
        self.model_name = model_name or os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        self.api_key = api_key
        self.timeout_ms = timeout_ms
        self.total_timeout_sec = total_timeout_sec

    def _get_client(self) -> tuple[Optional[Any], Optional[str]]:
        if not HAS_ANTHROPIC_SDK:
            return None, "anthropic Python SDK is not installed (pip install anthropic)"

        key = self.api_key or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY")
        if not key:
            return None, "ANTHROPIC_API_KEY environment variable is not configured in the current process environment"

        try:
            client = anthropic.Anthropic(
                api_key=key,
                timeout=self.timeout_ms / 1000.0,
                max_retries=0,
            )
            return client, None
        except Exception as e:
            return None, f"Failed to instantiate Anthropic client: {_sanitize_error(str(e))}"

    def get_info(self) -> Dict[str, Any]:
        """Return provider status and configuration info without leaking credentials."""
        client, err = self._get_client()
        is_configured = bool(self.api_key or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_API_KEY"))
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
                "message": f"Claude provider not ready: {info.get('error') or 'Missing configuration'}",
            }

        client, err = self._get_client()
        if not client:
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "success": False,
                "status": "error",
                "message": f"Claude client initialization failed: {err}",
            }

        def _do_test():
            response = client.messages.create(
                model=self.model_name,
                max_tokens=10,
                messages=[
                    {"role": "user", "content": "Say OK if you can read this."}
                ],
            )
            if response.content and len(response.content) > 0:
                return response.content[0].text
            return ""

        logger.info(f"Claude test_connection request started (model: {self.model_name})")
        try:
            _run_daemon_bounded(_do_test, total_timeout_sec=total_timeout_sec)
            logger.info("Claude response received successfully")
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "success": True,
                "status": "ready",
                "message": "Claude API connection successful",
            }
        except TimeoutError:
            logger.error("Claude API connection timed out")
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "success": False,
                "status": "error",
                "message": "Claude API connection timed out",
            }
        except Exception as ex:
            err_dict = _classify_claude_error(ex)
            err_dict["provider"] = self.provider_name
            err_dict["model"] = self.model_name
            err_dict["success"] = False
            logger.error(f"Claude API error category: {err_dict['status']}")
            return err_dict

    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        client, err = self._get_client()
        if not client:
            raise ValueError(f"Claude provider not initialized: {err}")

        def _do_generate():
            response = client.messages.create(
                model=self.model_name,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            if response.content and len(response.content) > 0:
                return response.content[0].text
            return ""

        logger.info(f"Claude generate request started (model: {self.model_name})")
        try:
            res = _run_daemon_bounded(_do_generate, total_timeout_sec=self.total_timeout_sec)
            logger.info("Claude response received successfully")
            return res
        except TimeoutError:
            logger.error("Claude API connection timed out")
            raise RuntimeError("Claude API Error: Claude API connection timed out")
        except Exception as ex:
            err_dict = _classify_claude_error(ex)
            logger.error(f"Claude API error category: {err_dict['status']}")
            raise RuntimeError(f"Claude API Error: {err_dict['message']} - {err_dict['details']}")

    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None) -> Dict[str, Any]:
        """Perform security context analysis using Claude."""
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
        if "Claude API Error:" in error_msg:
            error_msg = error_msg.replace("Claude API Error:", "").strip()
        elif "Claude provider not initialized:" in error_msg:
            error_msg = error_msg.replace("Claude provider not initialized:", "").strip()
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
