"""
NYX Local LLaMA / Ollama Agent Provider Integration
Connects to local AI server endpoint (default: Ollama native API at http://localhost:11434/api/generate)
with bounded timeouts, strict error classification, and fail-closed safety.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from nyx.ai.base import AIProvider

logger = logging.getLogger(__name__)

try:
    import requests
    _ORIGINAL_REQUESTS_POST = requests.post
    _ORIGINAL_REQUESTS_GET = requests.get
except ImportError:
    _ORIGINAL_REQUESTS_POST = None
    _ORIGINAL_REQUESTS_GET = None


def _is_requests_post_mocked() -> bool:
    """Check if requests.post has been patched/mocked by unittest.mock or pytest monkeypatch."""
    try:
        import requests
        import unittest.mock
        curr = requests.post
        if _ORIGINAL_REQUESTS_POST is not None and curr is not _ORIGINAL_REQUESTS_POST:
            return True
        if isinstance(curr, unittest.mock.Base):
            return True
    except Exception:
        pass
    return False


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
            "message": f"Local AI server connection refused{code_tag} (is server running at http://localhost:11434?): {err_str}",
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


def calculate_dynamic_timeout(
    token_budget: int,
    tok_per_sec: Optional[float] = None,
    fallback_timeout: float = 120.0,
) -> float:
    """
    Compute dynamic timeout = (token_budget / measured_tok_per_sec) * 1.5 safety margin,
    floored at 30.0s, capped at 600.0s.
    If tok_per_sec is unset or <= 0, returns fallback_timeout.
    """
    if tok_per_sec is None or tok_per_sec <= 0:
        return float(fallback_timeout)
    raw = (float(token_budget) / float(tok_per_sec)) * 1.5
    return float(max(30.0, min(600.0, raw)))


SERVER_OLLAMA = "ollama"
SERVER_OPENAI_COMPATIBLE = "openai_compatible"


class LocalLlamaProvider(AIProvider):
    """Local LLaMA / Ollama / OpenAI-compatible native HTTP Provider Implementation."""

    provider_name: str = "local"
    _cached_speed: Optional[float] = None
    _last_timeout_time: Optional[float] = None
    _last_timeout_cooldown: float = 5.0

    def __init__(
        self,
        model_name: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        health_url: Optional[str] = None,
        timeout_sec: float = 120.0,
    ):
        if model_name is not None and model_name not in ("local-llama", "local"):
            self.model_name = model_name
        else:
            self.model_name = (
                os.environ.get("LOCAL_LLM_MODEL")
                or os.environ.get("NYX_LOCAL_MODEL")
                or "qwen2.5-coder:7b"
            )
        self.endpoint_url = (
            endpoint_url
            or os.environ.get("LOCAL_LLM_URL")
            or os.environ.get("NYX_LOCAL_URL")
            or "http://localhost:11434/api/generate"
        )
        self.health_url = (
            health_url
            or os.environ.get("LOCAL_HEALTH_URL")
            or "http://localhost:11434/api/tags"
        )
        env_timeout = os.environ.get("LOCAL_TIMEOUT") or os.environ.get("NYX_LOCAL_TIMEOUT")
        self.timeout_sec = float(env_timeout) if env_timeout else timeout_sec

        # Server adapter configuration
        env_server = os.environ.get("LOCAL_LLM_SERVER_TYPE") or os.environ.get("NYX_LOCAL_SERVER_TYPE")
        if env_server:
            self.server_type = SERVER_OPENAI_COMPATIBLE if "openai" in env_server.lower() else SERVER_OLLAMA
        elif "/v1" in self.endpoint_url:
            self.server_type = SERVER_OPENAI_COMPATIBLE
        else:
            self.server_type = SERVER_OLLAMA

        self._model_explicitly_set = (model_name is not None and model_name not in ("local-llama", "local")) or bool(
            os.environ.get("LOCAL_LLM_MODEL") or os.environ.get("NYX_LOCAL_MODEL")
        )

        env_speed = os.environ.get("LOCAL_LLM_TOK_PER_SEC") or os.environ.get("NYX_LOCAL_TOK_PER_SEC")
        self.measured_tok_per_sec: Optional[float] = float(env_speed) if env_speed else LocalLlamaProvider._cached_speed
        if self.measured_tok_per_sec:
            logger.info("[AI:local] Using configured/cached local LLM speed: %.2f tok/s", self.measured_tok_per_sec)

        env_cooldown = os.environ.get("LOCAL_TIMEOUT_COOLDOWN") or os.environ.get("NYX_LOCAL_TIMEOUT_COOLDOWN")
        self.cooldown_sec: Optional[float] = float(env_cooldown) if env_cooldown else None

    def normalize_response(self, data: Any) -> str:
        """Extract text from either Ollama or OpenAI-compatible JSON responses."""
        if not isinstance(data, dict):
            raise ValueError(f"Local AI server returned non-dict JSON: {str(data)[:300]}")

        # 1. Native Ollama format: {"response": "..."}
        if "response" in data and data["response"] is not None:
            return str(data["response"])

        # 2. OpenAI-compatible format: {"choices": [{"message": {"content": "..."}}]}
        choices = data.get("choices")
        if choices and isinstance(choices, list) and len(choices) > 0:
            first_choice = choices[0]
            if isinstance(first_choice, dict):
                msg = first_choice.get("message")
                if isinstance(msg, dict) and msg.get("content") is not None:
                    return str(msg["content"])
                if first_choice.get("text") is not None:
                    return str(first_choice["text"])

        # 3. Fallbacks
        for k in ("content", "text"):
            if k in data and data[k] is not None:
                return str(data[k])

        raise ValueError(f"Local AI server response missing 'response' or 'choices' field: {str(data)[:300]}")

    def _build_payload(self, prompt: str, opts: Dict[str, Any], token_budget: int) -> tuple[str, Dict[str, Any]]:
        """Construct target endpoint URL and normalized JSON payload for target server."""
        want_json = bool(
            opts.get("format") == "json"
            or opts.get("json") is True
            or opts.get("response_format")
        )
        if self.server_type == SERVER_OPENAI_COMPATIBLE or "/v1" in self.endpoint_url:
            url = self.endpoint_url
            if url.endswith("/api/generate"):
                url = url.replace("/api/generate", "/v1/chat/completions")
            payload: Dict[str, Any] = {
                "model": self.model_name,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": token_budget,
                "stream": False,
            }
            if want_json:
                payload["response_format"] = {"type": "json_object"}
            if "temperature" in opts:
                try:
                    payload["temperature"] = float(opts["temperature"])
                except (ValueError, TypeError):
                    pass
            if "top_p" in opts:
                try:
                    payload["top_p"] = float(opts["top_p"])
                except (ValueError, TypeError):
                    pass
            return url, payload
        else:
            # Native Ollama /api/generate format
            ollama_opts: Dict[str, Any] = {"num_predict": token_budget}
            if "temperature" in opts:
                try:
                    ollama_opts["temperature"] = float(opts["temperature"])
                except (ValueError, TypeError):
                    pass
            if "top_p" in opts:
                try:
                    ollama_opts["top_p"] = float(opts["top_p"])
                except (ValueError, TypeError):
                    pass
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": ollama_opts,
            }
            if want_json:
                payload["format"] = "json"
            return self.endpoint_url, payload

    def _record_timeout_if_applicable(self, ex: Exception, timeout_val: float) -> None:
        """Record timeout occurrence to engage queue drain cooldown on subsequent requests."""
        err_str = str(ex).lower()
        if "timeout" in err_str or "timed out" in err_str:
            LocalLlamaProvider._last_timeout_time = time.time()
            LocalLlamaProvider._last_timeout_cooldown = (
                self.cooldown_sec if self.cooldown_sec is not None else min(30.0, max(5.0, timeout_val * 0.1))
            )

    def get_dynamic_timeout(self, token_budget: int, explicit_timeout: Optional[float] = None) -> float:
        """Calculate dynamic timeout for a given token budget with floor 30s and ceiling 600s."""
        speed = self.measured_tok_per_sec or LocalLlamaProvider._cached_speed
        if explicit_timeout is not None and speed is None:
            return float(explicit_timeout)
        return calculate_dynamic_timeout(
            token_budget=token_budget,
            tok_per_sec=speed,
            fallback_timeout=explicit_timeout if explicit_timeout is not None else self.timeout_sec,
        )

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
        """Test reachability of health and chat endpoints with auto-detection for Ollama and OpenAI servers."""
        if os.environ.get("NYX_MOCK_LLM") == "1" and not _is_requests_post_mocked():
            is_get_mocked = False
            try:
                import requests
                import unittest.mock
                if _ORIGINAL_REQUESTS_GET is not None and requests.get is not _ORIGINAL_REQUESTS_GET:
                    is_get_mocked = True
                elif isinstance(requests.get, unittest.mock.Base):
                    is_get_mocked = True
            except Exception:
                pass
            if not is_get_mocked:
                return {
                    "provider": self.provider_name,
                    "model": self.model_name,
                    "success": True,
                    "status": "ready",
                    "message": f"Local AI server (mock) connected successfully ({self.endpoint_url})",
                }

        logger.info(f"Testing local AI server connection at {self.endpoint_url}...")

        # 1. Health check probe and auto-detection
        h_data: Optional[Dict[str, Any]] = None
        try:
            try:
                import requests
                h_resp = requests.get(self.health_url, timeout=min(timeout_sec, 10.0))
                if h_resp.status_code == 200:
                    try:
                        h_data = h_resp.json()
                    except Exception:
                        pass
                else:
                    # If default Ollama health URL returned 404, probe OpenAI-compatible /v1/models
                    oai_health = (
                        self.health_url.replace("/api/tags", "/v1/models")
                        if "/api/tags" in self.health_url
                        else self.endpoint_url.split("/api/")[0].rstrip("/") + "/v1/models"
                    )
                    h_resp_oai = requests.get(oai_health, timeout=min(timeout_sec, 10.0))
                    if h_resp_oai.status_code == 200:
                        self.server_type = SERVER_OPENAI_COMPATIBLE
                        self.health_url = oai_health
                        if self.endpoint_url.endswith("/api/generate"):
                            self.endpoint_url = self.endpoint_url.replace("/api/generate", "/v1/chat/completions")
                        try:
                            h_data = h_resp_oai.json()
                        except Exception:
                            pass
                    else:
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
                    if resp.status == 200:
                        try:
                            h_data = json.loads(resp.read().decode("utf-8"))
                        except Exception:
                            pass
                    else:
                        return {
                            "provider": self.provider_name,
                            "model": self.model_name,
                            "success": False,
                            "status": "error",
                            "message": f"Local AI health check returned HTTP {resp.status}",
                        }

            # Auto-detect loaded model if model was not explicitly specified by the user
            if h_data and not self._model_explicitly_set:
                if "models" in h_data and isinstance(h_data["models"], list) and h_data["models"]:
                    avail = [m.get("name") for m in h_data["models"] if m.get("name")]
                    if avail and self.model_name not in avail:
                        self.model_name = avail[0]
                        logger.info("[AI:local] Auto-detected active Ollama model: %s", self.model_name)
                elif "data" in h_data and isinstance(h_data["data"], list) and h_data["data"]:
                    avail = [m.get("id") for m in h_data["data"] if m.get("id")]
                    if avail and self.model_name not in avail:
                        self.model_name = avail[0]
                        logger.info("[AI:local] Auto-detected active OpenAI-compatible model: %s", self.model_name)

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

    def _generate_deterministic_mock(self, prompt: str) -> str:
        """
        Generate realistic, deterministic structured responses when NYX_MOCK_LLM=1.
        Varies response based on prompt context to exercise parsing and branching logic.
        """
        p_lower = (prompt or "").lower()

        # 1. Health check / ping probe
        if "say ok if you can read this" in p_lower:
            return "OK. Connection verified."

        # 2. Autonomous candidate selection decision prompt (run_autonomous_loop)
        if (
            "policy-validated candidate steps" in p_lower
            or "selected_index" in p_lower
            or "select the most strategic candidate step" in p_lower
        ):
            if "sql" in p_lower:
                reasoning = "Prioritizing SQL injection verification step against detected database endpoints per methodology."
            elif "lfi" in p_lower or "traversal" in p_lower:
                reasoning = "Prioritizing path traversal and local file inclusion verification step against file endpoints."
            elif "recon" in p_lower or "discovery" in p_lower:
                reasoning = "Executing initial discovery and endpoint reconnaissance to expand target attack surface."
            else:
                reasoning = "Selected candidate step #0 based on security playbook methodology and risk prioritization."

            return json.dumps({
                "selected_index": 0,
                "decision": "proceed",
                "reasoning": reasoning,
            })

        # 3. Decision between multiple options (decide method)
        if "select the best security action index from the following options" in p_lower:
            return json.dumps({
                "selected_index": 0,
                "decision": "proceed",
                "reasoning": "Selected highest-priority security action index based on playbook rules.",
            })

        # 4. Finding hypothesis description enrichment (enrich_hypothesis_description)
        if "### why this was flagged" in p_lower or "analyzing a detected web attack surface hypothesis" in p_lower:
            return (
                "### Why This Was Flagged\n"
                "Automated pattern matching and heuristic analysis identified potential vulnerability exposure on the targeted endpoint parameter.\n\n"
                "### Exploitability Conditions\n"
                "Requires lack of input validation, unescaped syntax reflection, or insufficient authorization enforcement on the backend handler.\n\n"
                "### Verification Steps\n"
                "1. Perform non-invasive baseline probe to confirm parameter behavior.\n"
                "2. Verify response differential or timing variations.\n"
                "3. Note: Only proceed with data extraction after confirming vulnerability existence and with explicit client/engagement authorization for data access.\n\n"
                "### Status\n"
                "Unconfirmed hypothesis based on automated pattern matching. Requires empirical validation before confirming impact."
            )

        # 5. Finding triage JSON generation (triage_finding)
        if "vrt_category" in p_lower or "severity_justification" in p_lower:
            vuln_type = (
                "SQL Injection"
                if "sql" in p_lower
                else ("Cross-Site Scripting" if "xss" in p_lower else "API Security Misconfiguration")
            )
            return json.dumps({
                "vrt_category": f"Server-Side Injection > {vuln_type}",
                "severity_justification": "Direct parameter manipulation indicates high security risk with potential unauthorized data access.",
                "summary": f"The target endpoint exhibits potential {vuln_type} vulnerabilities due to insufficient input validation.",
                "steps_to_reproduce": "1. Send a crafted verification probe to the target endpoint.\n2. Observe abnormal response status or error syntax reflecting vulnerability.",
                "impact": "An attacker could leverage this vulnerability to gain unauthorized access to backend data or system functionality.",
                "remediation": "Implement parameterized queries, strict input validation, and context-aware output encoding.",
            })

        # 6. Finding evidence review / verification
        if "evidence review" in p_lower or "verdict:" in p_lower or "review the evidence collected" in p_lower:
            return (
                "VERDICT: CONFIRMED\n"
                "REASONING: Empirical request/response evidence demonstrates observable behavioral differences confirming vulnerability existence."
            )

        # 7. Mission planning or context analysis prompt (create_plan, analyze)
        if (
            "tailored" in p_lower
            or "hypothesis" in p_lower
            or "vulnerability research focus" in p_lower
            or "detected technologies:" in p_lower
            or "vulnerability_type" in p_lower
            or "focus particularly on analyzing attack vectors" in p_lower
        ):
            if "sql" in p_lower:
                focus = "SQL Injection & Parameterized Data Exposure"
                reasoning = "Target endpoints and parameters exhibit dynamic query patterns. Prioritizing structured SQL syntax validation."
            elif "lfi" in p_lower or "traversal" in p_lower:
                focus = "Local File Inclusion & Path Traversal"
                reasoning = "Endpoint routing indicates potential file retrieval parameters without canonical path normalization."
            elif "xss" in p_lower:
                focus = "Cross-Site Scripting & Client Sink Reflection"
                reasoning = "Client-side reflection sinks detected in harvested endpoints. Prioritizing context-aware payload verification."
            elif "recon" in p_lower or "discovery" in p_lower:
                focus = "Target Asset Discovery & Surface Enumeration"
                reasoning = "Initial engagement phase prioritizing endpoint harvesting and technology fingerprinting."
            else:
                focus = "API & Authentication Boundary Verification"
                reasoning = "Target endpoints and detected stack indicate public service surface requiring credential and authorization boundary verification."

            return json.dumps({
                "focus": focus,
                "recommended_focus": focus,
                "reasoning": reasoning,
                "analysis": reasoning,
            })

        # 8. Generic JSON fallback
        return json.dumps({
            "focus": "Security Surface Analysis",
            "recommended_focus": "Security Surface Analysis",
            "reasoning": "Deterministic mock reasoning from NYX AI test harness.",
            "analysis": "Deterministic mock reasoning from NYX AI test harness.",
            "selected_index": 0,
            "decision": "proceed",
            "status": "success",
        })

    def generate(self, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
        """Send prompt to local Ollama /api/generate endpoint and return text response."""
        opts = options or {}

        # Fast path: deterministic structured mock for regression test suites
        if os.environ.get("NYX_MOCK_LLM") == "1" and not _is_requests_post_mocked():
            logger.debug("[AI:local] NYX_MOCK_LLM active: returning deterministic structured mock response")
            return self._generate_deterministic_mock(prompt)

        explicit_timeout = float(opts["timeout"]) if "timeout" in opts and opts["timeout"] is not None else None

        max_tokens = (
            opts.get("num_predict")
            or opts.get("max_completion_tokens")
            or opts.get("max_tokens")
            or int(os.environ.get("LOCAL_MAX_TOKENS") or os.environ.get("NYX_LOCAL_MAX_TOKENS") or 1024)
        )
        try:
            token_budget = int(max_tokens)
        except (ValueError, TypeError):
            token_budget = 1024

        timeout = self.get_dynamic_timeout(token_budget=token_budget, explicit_timeout=explicit_timeout)
        target_url, payload_data = self._build_payload(prompt, opts, token_budget)

        # Engage post-timeout cooldown before dispatching if a recent timeout occurred
        if LocalLlamaProvider._last_timeout_time is not None:
            cooldown_target = (
                self.cooldown_sec
                if self.cooldown_sec is not None
                else LocalLlamaProvider._last_timeout_cooldown
            )
            elapsed_since_to = time.time() - LocalLlamaProvider._last_timeout_time
            if elapsed_since_to < cooldown_target:
                wait_sec = cooldown_target - elapsed_since_to
                logger.info(
                    "[AI:local] Post-timeout queue cooldown active; waiting %.1fs for server queue to drain...",
                    wait_sec,
                )
                time.sleep(wait_sec)
            LocalLlamaProvider._last_timeout_time = None

        def _calibrate_speed(data_dict: Dict[str, Any], text_resp: str, elapsed_time: float) -> None:
            eval_count = data_dict.get("eval_count")
            eval_duration = data_dict.get("eval_duration")
            speed = None
            if eval_count and eval_duration and eval_duration > 0:
                speed = float(eval_count) / (float(eval_duration) / 1e9)
            elif elapsed_time > 0 and len(text_resp) > 0:
                approx_tokens = max(1.0, len(text_resp.split()) * 1.3)
                speed = approx_tokens / elapsed_time
            if speed and speed > 0:
                self.measured_tok_per_sec = speed
                LocalLlamaProvider._cached_speed = speed
                logger.info(
                    "[AI:local] Calibrated local LLM inference speed: %.2f tok/s (model: %s)",
                    speed,
                    self.model_name,
                )

        logger.info("[AI:local] Dispatching prompt to local LLM (%s) at %s (timeout: %ds, tokens: %d)...", self.model_name, target_url, int(timeout), token_budget)
        t_start = time.time()
        try:
            import requests
            resp = requests.post(
                target_url,
                json=payload_data,
                headers={"Content-Type": "application/json", "User-Agent": "NYX-AI-Local/1.0"},
                timeout=timeout,
            )
            # If server returned 400 because structured format is unsupported, retry without it
            if resp.status_code == 400 and ("format" in payload_data or "response_format" in payload_data):
                logger.warning(
                    "[AI:local] Server rejected structured JSON request parameter (HTTP 400); retrying without it..."
                )
                payload_fallback = payload_data.copy()
                payload_fallback.pop("format", None)
                payload_fallback.pop("response_format", None)
                resp = requests.post(
                    target_url,
                    json=payload_fallback,
                    headers={"Content-Type": "application/json", "User-Agent": "NYX-AI-Local/1.0"},
                    timeout=timeout,
                )
            elapsed = time.time() - t_start
            if resp.status_code == 200:
                data = resp.json()
                response_text = self.normalize_response(data)
                _calibrate_speed(data, response_text, elapsed)
                logger.info("[AI:local] Local LLM response received (elapsed: %.1fs, model: %s)", elapsed, self.model_name)
                return response_text
            else:
                raise RuntimeError(f"Local AI Server Error (HTTP {resp.status_code}): {resp.text[:300]}")
        except ImportError:
            payload = json.dumps(payload_data).encode("utf-8")
            req = urllib.request.Request(
                target_url,
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
                    elapsed = time.time() - t_start
                    body = resp.read().decode("utf-8")
                    data = json.loads(body)
                    response_text = self.normalize_response(data)
                    _calibrate_speed(data, response_text, elapsed)
                    return response_text
            except urllib.error.HTTPError as ex:
                elapsed = time.time() - t_start
                err_body = ""
                try:
                    err_body = ex.read().decode("utf-8")
                except Exception:
                    pass
                classified = _classify_local_error(ex)
                logger.warning(
                    "[AI:local] Request failed/timed out after %.1fs: %s %s",
                    elapsed,
                    classified["message"],
                    err_body,
                )
                raise RuntimeError(f"Local AI Server Error (HTTP {ex.code}): {classified['message']} {err_body}") from ex
            except urllib.error.URLError as ex:
                elapsed = time.time() - t_start
                classified = _classify_local_error(ex.reason if hasattr(ex, "reason") else ex)
                logger.warning(
                    "[AI:local] Request failed/timed out after %.1fs: %s",
                    elapsed,
                    classified["message"],
                )
                raise RuntimeError(f"Local AI Connection Error: {classified['message']}") from ex
            except Exception as ex:
                elapsed = time.time() - t_start
                classified = _classify_local_error(ex)
                logger.warning(
                    "[AI:local] Request failed/timed out after %.1fs: %s",
                    elapsed,
                    classified["message"],
                )
                raise RuntimeError(f"Local AI Server Error: {classified['message']}") from ex
        except Exception as ex:
            self._record_timeout_if_applicable(ex, timeout)
            elapsed = time.time() - t_start
            classified = _classify_local_error(ex)
            logger.warning(
                "[AI:local] Request failed/timed out after %.1fs: %s",
                elapsed,
                classified["message"],
            )
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

        # Scale timeout dynamically with candidate count / context size
        candidate_count = len(context.get("validated_candidates") or context.get("endpoints") or [])
        scaled_timeout = max(self.timeout_sec, min(300.0, self.timeout_sec + candidate_count * 2.5))

        try:
            generated = self.generate(custom_prompt, options={"timeout": scaled_timeout, "format": "json"})
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
