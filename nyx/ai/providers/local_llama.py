"""
NYX Local LLaMA / DeepSeek Agent Provider Integration
Connects to local AI server endpoint (default: http://localhost:8000/chat)
with bounded timeouts, strict error classification, and fail-closed safety.
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from nyx.ai.base import AIProvider

logger = logging.getLogger(__name__)


def _classify_local_error(ex: Exception) -> Dict[str, Any]:
    """Classify and normalize local AI server exceptions into clean error structures."""
    if ex is None:
        return {"status": "error", "message": "Unknown local provider error", "details": "", "status_code": None}

    status_code = getattr(ex, "code", None) or getattr(ex, "status_code", None)
    err_str = str(ex)
    err_lower = err_str.lower()
    code_tag = f" [HTTP {status_code}]" if status_code else ""

    if "timed out" in err_lower or "timeout" in err_lower:
        return {
            "status": "error",
            "error_type": "timeout",
            "message": f"Local AI server connection timed out{code_tag}: {err_str}",
            "details": err_str,
            "status_code": status_code,
        }
    if "connection refused" in err_lower or "cannot connect" in err_lower or "failed to establish a new connection" in err_lower:
        return {
            "status": "error",
            "error_type": "connection_refused",
            "message": f"Local AI server connection refused{code_tag} (is server running at http://localhost:8000?): {err_str}",
            "details": err_str,
            "status_code": status_code,
        }
    if "429" in err_lower or "rate limit" in err_lower:
        return {
            "status": "error",
            "error_type": "rate_limit",
            "message": f"Local AI server rate limit reached{code_tag}: {err_str}",
            "details": err_str,
            "status_code": status_code,
        }

    return {
        "status": "error",
        "error_type": "provider_error",
        "message": f"Local AI server error{code_tag}: {err_str}",
        "details": err_str,
        "status_code": status_code,
    }


class LocalLlamaProvider(AIProvider):
    """Local LLaMA / DeepSeek HTTP Provider Implementation."""

    provider_name: str = "local"

    def __init__(
        self,
        model_name: str = "local-llama",
        endpoint_url: Optional[str] = None,
        health_url: Optional[str] = None,
        timeout_sec: float = 60.0,
    ):
        self.model_name = model_name
        self.endpoint_url = (
            endpoint_url
            or os.environ.get("LOCAL_LLM_URL")
            or os.environ.get("NYX_LOCAL_URL")
            or "http://localhost:8000/chat"
        )
        self.health_url = (
            health_url
            or os.environ.get("LOCAL_HEALTH_URL")
            or "http://localhost:8000/health"
        )
        self.timeout_sec = timeout_sec

    def get_info(self) -> Dict[str, Any]:
        """Return provider status and configuration info."""
        configured = bool(self.endpoint_url)
        return {
            "name": self.provider_name,
            "type": self.__class__.__name__,
            "status": "ready" if configured else "unavailable",
            "configured": configured,
            "model": self.model_name,
            "endpoint": self.endpoint_url,
            "health_endpoint": self.health_url,
        }

    def test_connection(self, timeout_sec: float = 45.0) -> Dict[str, Any]:
        """Test reachability of health and chat endpoints."""
        logger.info(f"Testing local AI server connection at {self.endpoint_url}...")

        # 1. Health check probe
        try:
            try:
                import requests
                h_resp = requests.get(self.health_url, timeout=min(timeout_sec, 10.0))
                if h_resp.status_code != 200:
                    return {
                        "provider": self.provider_name,
                        "model": self.model_name,
                        "success": False,
                        "status": "error",
                        "message": f"Local AI health check returned HTTP {h_resp.status_code}",
                    }
            except ImportError:
                req = urllib.request.Request(
                    self.health_url,
                    headers={"User-Agent": "NYX-AI-Local/1.0", "Connection": "close"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=min(timeout_sec, 10.0)) as resp:
                    if resp.status != 200:
                        return {
                            "provider": self.provider_name,
                            "model": self.model_name,
                            "success": False,
                            "status": "error",
                            "message": f"Local AI health check returned HTTP {resp.status}",
                        }
        except Exception as ex:
            err_dict = _classify_local_error(ex)
            err_dict["provider"] = self.provider_name
            err_dict["model"] = self.model_name
            err_dict["success"] = False
            logger.error("Local AI server health check failed: %s", err_dict["message"])
            return err_dict

        # 2. Chat completion probe
        try:
            test_resp = self.generate("Say OK if you can read this.", options={"timeout": timeout_sec})
            if test_resp and len(test_resp.strip()) > 0:
                return {
                    "provider": self.provider_name,
                    "model": self.model_name,
                    "success": True,
                    "status": "ready",
                    "message": f"Local AI server connected successfully ({self.endpoint_url})",
                }
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "success": False,
                "status": "error",
                "message": "Local AI server returned empty test response",
            }
        except Exception as ex:
            err_dict = _classify_local_error(ex)
            err_dict["provider"] = self.provider_name
            err_dict["model"] = self.model_name
            err_dict["success"] = False
            return err_dict

    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        """Send prompt to local server /chat endpoint and return text response."""
        opts = options or {}
        timeout = float(opts.get("timeout") or self.timeout_sec)

        try:
            import requests
            resp = requests.post(
                self.endpoint_url,
                json={"prompt": prompt},
                headers={"Content-Type": "application/json", "User-Agent": "NYX-AI-Local/1.0"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict):
                    response_text = data.get("response") or data.get("content") or data.get("text")
                    if response_text is not None:
                        return str(response_text)
                    raise ValueError(f"Local AI server response missing 'response' field: {resp.text[:300]}")
                raise ValueError(f"Local AI server returned non-dict JSON: {resp.text[:300]}")
            else:
                raise RuntimeError(f"Local AI Server Error (HTTP {resp.status_code}): {resp.text[:300]}")
        except ImportError:
            payload = json.dumps({"prompt": prompt}).encode("utf-8")
            req = urllib.request.Request(
                self.endpoint_url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "NYX-AI-Local/1.0",
                    "Connection": "close",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8")
                    data = json.loads(body)
                    if isinstance(data, dict):
                        response_text = data.get("response") or data.get("content") or data.get("text")
                        if response_text is not None:
                            return str(response_text)
                        raise ValueError(f"Local AI server response missing 'response' field: {body[:300]}")
                    raise ValueError(f"Local AI server returned non-dict JSON: {body[:300]}")
            except urllib.error.HTTPError as ex:
                err_body = ""
                try:
                    err_body = ex.read().decode("utf-8")
                except Exception:
                    pass
                classified = _classify_local_error(ex)
                raise RuntimeError(f"Local AI Server Error (HTTP {ex.code}): {classified['message']} {err_body}") from ex
            except urllib.error.URLError as ex:
                classified = _classify_local_error(ex.reason if hasattr(ex, "reason") else ex)
                raise RuntimeError(f"Local AI Connection Error: {classified['message']}") from ex
            except Exception as ex:
                classified = _classify_local_error(ex)
                raise RuntimeError(f"Local AI Server Error: {classified['message']}") from ex
        except Exception as ex:
            classified = _classify_local_error(ex)
            raise RuntimeError(f"Local AI Server Error: {classified['message']}") from ex

    def analyze(self, context: Dict[str, Any], prompt: Optional[str] = None) -> Dict[str, Any]:
        """Perform security context analysis or autonomous candidate selection using local AI."""
        target = context.get("target", "unknown")
        technologies = context.get("technologies", [])
        endpoints = context.get("endpoints", [])
        phase = context.get("phase", "DISCOVERY")

        if prompt:
            # Wrap custom prompt with explicit instruction headers to ensure structured JSON output
            custom_prompt = (
                "### Instruction:\n"
                "You are an AI decision engine for NYX. Analyze the context and candidate steps below. "
                "Respond ONLY with a single JSON object. Do not include conversational remarks, greetings, or explanations outside JSON.\n\n"
                f"### Context & Task:\n{prompt}\n\n"
                "### Output JSON Format:\n"
                "Respond ONLY with valid JSON starting with { and ending with }."
            )
        else:
            custom_prompt = (
                "### Instruction:\n"
                "You are an AI security analyzer for NYX. Analyze the target reconnaissance data below.\n"
                f"Target: {target}\n"
                f"Phase: {phase}\n"
                f"Detected Technologies: {technologies[:15]}\n"
                f"Harvested Endpoints Count: {len(endpoints)}\n\n"
                "Provide a tailored vulnerability research focus.\n"
                "Respond ONLY with a valid JSON object with exactly these keys:\n"
                "{\n"
                '  "focus": "<short focus area, a few words>",\n'
                '  "reasoning": "<concise explanation referencing technologies and attack surface>"\n'
                "}"
            )

        try:
            generated = self.generate(custom_prompt)
        except Exception as ex:
            err_dict = _classify_local_error(ex)
            return {
                "provider": self.provider_name,
                "model": self.model_name,
                "target": target,
                "status": "error",
                "error": err_dict["message"],
                "error_type": err_dict["error_type"],
                "recommended_focus": "AI analysis unavailable",
                "analysis": err_dict["message"],
            }

        # Parse JSON output from model response
        clean_text = (generated or "").strip()
        if clean_text.startswith("```"):
            lines = clean_text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            clean_text = "\n".join(lines).strip()

        data: Optional[Dict[str, Any]] = None
        try:
            data = json.loads(clean_text)
        except Exception:
            m = re.search(r'\{.*\}', clean_text, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(0))
                except Exception:
                    pass

        if isinstance(data, dict):
            focus = data.get("focus") or data.get("decision") or data.get("recommended_focus")
            reasoning = data.get("reasoning") or data.get("analysis") or clean_text
            res_dict: Dict[str, Any] = {
                "provider": self.provider_name,
                "model": self.model_name,
                "target": target,
                "analysis": str(reasoning),
                "recommended_focus": str(focus or "AI decision"),
                "status": "success",
            }
            res_dict.update(data)
            return res_dict

        # If unparseable, return error dict to enforce fail-closed behavior
        return {
            "provider": self.provider_name,
            "model": self.model_name,
            "target": target,
            "status": "error",
            "error": f"Unparseable local AI response: {clean_text[:200]}",
            "error_type": "unparseable_ai_response",
            "recommended_focus": "AI analysis unavailable",
            "analysis": clean_text or "Local AI model returned unparseable text",
        }

    def decide(self, context: Dict[str, Any], options: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Make a security action decision using local AI."""
        if not options:
            return {"action": "none", "reason": "No options provided."}

        opts_summary = [
            {"index": i, "action": opt.get("action", f"option_{i}"), "description": opt.get("description", "")}
            for i, opt in enumerate(options)
        ]

        prompt = (
            "Select the best security action index from the following options:\n"
            f"{json.dumps(opts_summary, indent=2)}\n\n"
            "Respond ONLY with a JSON object: {\"selected_index\": <int>, \"decision\": \"<action>\", \"reasoning\": \"<explanation>\"}"
        )

        res = self.analyze(context, prompt=prompt)
        if isinstance(res, dict) and res.get("status") != "error":
            idx = res.get("selected_index")
            if isinstance(idx, int) and 0 <= idx < len(options):
                chosen = options[idx]
                return {
                    "provider": self.provider_name,
                    "decision": chosen.get("action", "unknown"),
                    "option": chosen,
                    "confidence": 0.85,
                    "reasoning": res.get("reasoning", ""),
                }

        chosen = options[0]
        return {
            "provider": self.provider_name,
            "decision": chosen.get("action", "unknown"),
            "option": chosen,
            "confidence": 0.50,
        }
