"""
NYX Mission Reasoning Engine & Planner
Converts AI decisions into structured, policy-validated NYX security missions.
"""
from __future__ import annotations

from pathlib import Path
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from nyx.ai.context import ContextEngine
from nyx.ai.manager import AIManager
from nyx.ai.memory import AIMemory
from nyx.security.ai_policy import AIPolicyEngine
from nyx.infrastructure.logging import get_logger

logger = get_logger("nyx.ai")


class MissionPlanner:
    """Converts high-level AI analysis into structured, policy-validated security missions."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir
        self.context_engine = ContextEngine(base_dir=base_dir)
        self.ai_manager = AIManager()
        self.policy_engine = AIPolicyEngine(base_dir=base_dir)
        self.memory = AIMemory(base_dir=base_dir)

    @staticmethod
    def _is_vector_already_tested(tested_vectors: List[Any], vector_name: str, endpoint: Optional[str] = None) -> bool:
        """Check if a security vector has already been tested on the target/endpoint with conclusive results."""
        for tv in tested_vectors:
            if not isinstance(tv, dict):
                continue
            v = str(tv.get("vector") or tv.get("name") or "")
            res = str(tv.get("result") or tv.get("status") or "")
            ep = tv.get("endpoint")
            if v.lower() == vector_name.lower():
                if endpoint and ep and endpoint != ep:
                    continue
                if res.lower() in ("tested_negative", "tested_success", "blocked_by_policy", "manual_action_required", "tested_skipped", "denied_by_operator", "operator_denied", "denied", "blocked"):
                    return True
        return False

    def _is_idor_candidate_endpoint(self, url: str, matches: Dict[str, Any]) -> bool:
        """
        Check if an endpoint actually represents an IDOR/BOLA candidate surface.
        Requires explicit object identifier patterns in path segments or query params.
        Rejects root paths '/', bare domain names, and static/informational assets.
        Supports router parameters (?page=, ?view=) in PHP front-controllers.
        """
        clean_url = (url or "").strip().lower()
        if not clean_url or clean_url in ("/", "http://", "https://"):
            return False
        
        parsed = urllib.parse.urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
        path = parsed.path
        query = parsed.query

        # Exclude static/metadata files and bare root
        if path in ("", "/", "/robots.txt", "/security.txt", "/favicon.ico", "/server-status", "/health"):
            return False
        if any(path.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".txt", ".map"]):
            return False

        # Extract effective paths for router-based architectures (?page=..., ?action=...)
        from nyx.core.analysis import extract_router_targets
        target_segments = extract_router_targets(clean_url)

        # 1. Query parameter object identifiers (e.g. ?id=123, ?user_id=45, ?account_id=..., ?uuid=...)
        id_param_pattern = re.compile(r"(^|[&?])(id|user_?id|account_?id|profile_?id|order_?id|invoice_?id|report_?id|doc_?id|file_?id|item_?id|basket_?id|cart_?id|uid|uuid)=([^&#]+)", re.I)
        if id_param_pattern.search(query):
            return True

        # 2. Path segment object identifiers across all target segments (e.g. /api/users/123, /rest/user/1, /orders/4b90...)
        uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        numeric_seg_pattern = r"/(users?|accounts?|profiles?|orders?|invoices?|items?|documents?|reports?|messages?|records?|files?|customers?|baskets?|products?)/(\d+|" + uuid_pattern + r")(/|$)"
        for seg in target_segments:
            if re.search(numeric_seg_pattern, seg, re.I):
                return True

        # 3. Explicit regex match from core_analysis where an ID parameter was matched
        if "hunt-idor" in matches and any(k in str(matches.get("hunt-idor", "")).lower() for k in ["id=", "user", "uid", "account", "order", "invoice"]):
            return True

        return False

    def _map_classification_to_hypotheses(
        self,
        classified_results: List[Dict[str, Any]],
        target: str,
    ) -> List[Dict[str, Any]]:
        """Bridge classification results to hypothesis findings in findings.json."""
        from nyx.application.finding_service import FindingService
        from nyx.core.analysis import extract_router_targets
        finding_svc = FindingService(base_dir=self.base_dir)
        created = []

        for item in classified_results:
            url = item.get("url") or target
            cat = str(item.get("category") or "").upper()
            skills = item.get("skills") or []
            matches = item.get("matches") or {}

            clean_url = (url or "").strip().lower()
            parsed = urllib.parse.urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
            path = parsed.path
            query = parsed.query

            # Skip bare roots and static assets from all hypothesis generation
            if path in ("", "/", "/robots.txt", "/security.txt", "/favicon.ico", "/server-status", "/health") and not query:
                continue
            if any(path.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2", ".txt", ".map"]):
                continue

            # Extract effective paths and router targets (e.g. ?page=user-info.php -> /user-info.php)
            effective_paths = extract_router_targets(clean_url)
            vuln_candidates = []

            # 1. SQL Injection (matches expanded parameters or SQLi-indicative sub-resources)
            sqli_param_pattern = re.compile(
                r"(^|[&?])(q|query|search|filter|cat|category|item|sort|order_by|select|username|user|user_id|uid|id|password|pass|email|name|account|number|author|blog_entry)=([^&#]+)",
                re.I
            )
            is_sqli_page = any(k in p for p in effective_paths for k in ["user-info", "view-someones-blog", "show-log", "sql", "database"])
            if ("hunt-sqli" in matches or "sqli" in matches) or sqli_param_pattern.search(query) or is_sqli_page:
                vuln_candidates.append({
                    "title": f"SQL Injection Surface on {url}",
                    "vulnerability": "SQL Injection",
                    "severity": "High",
                    "tag": "sqli,database",
                    "description": f"Classification identified parameter input surfaces on {url} matching SQL injection vulnerability patterns.",
                })

            # 2. Command Injection / OS Command Execution (parameters/endpoints: cmd, exec, ping, dns, lookup, host)
            cmd_param_pattern = re.compile(
                r"(^|[&?])(cmd|exec|command|run|ping|host|lookup|dns|ip|target_host|domain|address)=([^&#]+)",
                re.I
            )
            is_cmd_page = any(k in p for p in effective_paths for k in ["dns-lookup", "command-injection", "ping", "traceroute", "exec", "shell", "terminal"])
            if is_cmd_page or cmd_param_pattern.search(query) or ("hunt-rce" in matches and (is_cmd_page or cmd_param_pattern.search(query))):
                vuln_candidates.append({
                    "title": f"OS Command Injection Surface on {url}",
                    "vulnerability": "Command Injection",
                    "severity": "Critical",
                    "tag": "rce,command-injection,os",
                    "description": f"Classification identified system command execution or network utility parameter on {url} matching OS command injection patterns.",
                })

            # 3. IDOR / Broken Object Level Authorization (requires actual object identifier pattern)
            if self._is_idor_candidate_endpoint(url, matches):
                vuln_candidates.append({
                    "title": f"IDOR & Broken Object Level Authorization on {url}",
                    "vulnerability": "IDOR",
                    "severity": "High",
                    "tag": "idor,api,bola",
                    "description": f"Classification identified API resource routes on {url} exposing object identifier parameters prone to cross-tenant authorization bypass.",
                })

            # 4. Differentiated Authentication, Session, and Account Recovery Flaws
            # 4a. Password Reset & Account Recovery Flows
            if any(k in p for p in effective_paths for k in ["/forgot", "/forget-password", "/reset-password", "/recovery", "/password-reset", "/reset_password", "account-recovery"]):
                vuln_candidates.append({
                    "title": f"Password Recovery & Reset Flow Flaw on {url}",
                    "vulnerability": "Broken Password Recovery",
                    "severity": "High",
                    "tag": "auth,password-reset,ato",
                    "description": f"Classification identified password recovery or account reset workflow on {url} requiring token entropy, replay protection, and rate-limit validation.",
                })
            # 4b. Multi-Factor Authentication & OTP Validation Flows
            elif any(k in p for p in effective_paths for k in ["/otp", "/check-otp", "/verify-otp", "/2fa", "/mfa", "/verify", "/challenge"]):
                vuln_candidates.append({
                    "title": f"Multi-Factor Authentication & OTP Validation Flaw on {url}",
                    "vulnerability": "MFA Bypass",
                    "severity": "High",
                    "tag": "auth,mfa,otp",
                    "description": f"Classification identified multi-factor or one-time password verification endpoint on {url} requiring concurrency, race-condition, and brute-force protection analysis.",
                })
            # 4c. Token-Based, Bearer, and Refresh Token Flows
            elif any(k in p for p in effective_paths for k in ["/login-with-token", "/token", "/jwt", "/refresh-token", "/oauth/token", "/exchange", "/jwks"]):
                vuln_candidates.append({
                    "title": f"Token-Based Authentication & Session Handling Flaw on {url}",
                    "vulnerability": "Token Handling Flaw",
                    "severity": "High",
                    "tag": "auth,jwt,token",
                    "description": f"Classification identified token-based login or bearer authentication exchange on {url} requiring signature validation, expiration, and key confusion analysis.",
                })
            # 4d. Account Unlock & Lockout Mechanism
            elif any(k in p for p in effective_paths for k in ["/unlock", "/reactivate", "/lockout"]):
                vuln_candidates.append({
                    "title": f"Account Unlock & Lockout Mechanism Flaw on {url}",
                    "vulnerability": "Account Lockout Bypass",
                    "severity": "Medium",
                    "tag": "auth,lockout,state",
                    "description": f"Classification identified account unlock or lockout recovery mechanism on {url} requiring state validation and authorization controls.",
                })
            # 4e. User Registration & Provisioning
            elif any(k in p for p in effective_paths for k in ["/signup", "/register", "/create-account", "/user/create", "/provision"]):
                vuln_candidates.append({
                    "title": f"Account Registration & User Provisioning Flaw on {url}",
                    "vulnerability": "Insecure Registration",
                    "severity": "Medium",
                    "tag": "auth,registration,provisioning",
                    "description": f"Classification identified self-registration workflow on {url} requiring mass-assignment, role-injection, and identity verification analysis.",
                })
            # 4f. Primary Authentication Gateway / Session Login
            elif any(k in p for p in effective_paths for k in ["/login", "/signin", "/authenticate", "/session", "/oauth", "/saml", "/auth", "login.php"]) or any(s in matches for s in ("hunt-auth-bypass", "hunt-ato", "hunt-oauth", "hunt-saml")):
                vuln_candidates.append({
                    "title": f"Primary Authentication & Session State Flaw on {url}",
                    "vulnerability": "Authentication Bypass",
                    "severity": "High",
                    "tag": "auth,session,login",
                    "description": f"Classification identified primary authentication gateway on {url} requiring credential stuffing, brute-force, and session fixation validation.",
                })

            # 5. GraphQL Introspection & Mutation Flaws
            if any("/graphql" in p for p in effective_paths) or any(s in matches for s in ("hunt-graphql", "hunt-fintech-graphql")):
                vuln_candidates.append({
                    "title": f"GraphQL Introspection & Query Surface on {url}",
                    "vulnerability": "GraphQL",
                    "severity": "Medium",
                    "tag": "graphql,api",
                    "description": f"Classification identified GraphQL endpoint on {url} exposing query and mutation schema introspection.",
                })

            # 6. File Upload / Path Traversal / LFI
            is_file_page = any(k in p for p in effective_paths for k in ["/upload", "/attachment", "/avatar", "/file", "/import-xml", "/media", "arbitrary-file-inclusion", "file-upload", "upload"])
            if is_file_page or any(s in matches for s in ("hunt-file-upload", "hunt-lfi")):
                vuln_candidates.append({
                    "title": f"File Upload & Path Traversal Surface on {url}",
                    "vulnerability": "Arbitrary File Upload" if any("upload" in p for p in effective_paths) else "Local File Inclusion",
                    "severity": "High",
                    "tag": "file_upload,lfi",
                    "description": f"Classification identified file processing or path inclusion surface on {url}.",
                })

            # 7. SSRF / Open Redirect
            if (query and any(k in query for k in ["url=", "next=", "redirect=", "return=", "callback=", "dest=", "target="])) or any(s in matches for s in ("hunt-ssrf", "hunt-open-redirect")):
                vuln_candidates.append({
                    "title": f"Server-Side Request Forgery Surface on {url}",
                    "vulnerability": "SSRF",
                    "severity": "High",
                    "tag": "ssrf,redirect",
                    "description": f"Classification identified URL redirect or external request dispatch parameter on {url}.",
                })

            # 8. Cross-Site Scripting (XSS) (expanded parameters and CMS/blog pages)
            xss_param_pattern = re.compile(
                r"(^|[&?])(q|query|s|search|msg|name|comment|content|body|text|title|description|blog|message|feedback|heading|note|input|author)=([^&#]+)",
                re.I
            )
            is_xss_page = any(k in p for p in effective_paths for k in ["add-to-your-blog", "view-someones-blog", "html5-storage", "javascript", "xss"])
            if is_xss_page or ("hunt-xss" in matches or "hunt-html-injection" in matches) or (query and xss_param_pattern.search(query)):
                if not any(vc["vulnerability"] == "Cross-Site Scripting" for vc in vuln_candidates):
                    vuln_candidates.append({
                        "title": f"Cross-Site Scripting Surface on {url}",
                        "vulnerability": "Cross-Site Scripting",
                        "severity": "Medium",
                        "tag": "xss,client-side",
                        "description": f"Classification identified parameter reflection surface on {url} matching XSS vulnerability patterns.",
                    })

            for vc in vuln_candidates:
                try:
                    f_res = finding_svc.create(
                        title=vc["title"],
                        endpoint=url,
                        vulnerability=vc["vulnerability"],
                        severity=vc["severity"],
                        tag=vc["tag"],
                        description=vc["description"],
                        target=target,
                    )
                    if isinstance(f_res, dict) and not f_res.get("is_duplicate") and f_res.get("status") != "error":
                        fid = f_res.get("finding_id")
                        if fid:
                            try:
                                finding_svc.enrich(fid)
                            except Exception:
                                pass
                        created.append(f_res)
                except Exception:
                    pass

        return created

    def _select_steps(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Select and renumber mission plan steps based on target intelligence context, tested vectors, and knowledge."""
        target_name = context.get("target") or context.get("domain") or "target"
        endpoints = context.get("endpoints") or []
        technologies = [str(t) for t in (context.get("technologies") or []) if t]
        findings = context.get("findings") or context.get("previous_findings") or []
        tested_vectors = context.get("tested_vectors") or []
        relevant_k = context.get("relevant_knowledge") or {}
        rec_skills = relevant_k.get("recommended_skills") or ["skill-routing-engine"]
        vulnerability_type = context.get("vulnerability_type")

        hypothesis_findings_raw = [
            f
            for f in findings
            if isinstance(f, dict) and (f.get("state") or f.get("status") or "").upper() == "HYPOTHESIS"
        ]
        hypothesis_ids = [
            f.get("finding_id", "hyp-001")
            for f in hypothesis_findings_raw
        ]
        has_hypothesis = len(hypothesis_ids) > 0

        selected: List[Dict[str, Any]] = []

        if not endpoints:
            # Rule 1: No Endpoints (Full Discovery Phase Pipeline)
            if not self._is_vector_already_tested(tested_vectors, "httpx_execution"):
                selected.append({
                    "name": "Technology Fingerprinting",
                    "action": "passive_recon",
                    "tool": "httpx",
                    "description": "Probe live host, HTTP headers, titles, and technology stack.",
                    "reason": "INITIAL_HOST_DISCOVERY",
                    "evidence": [target_name],
                    "knowledge_refs": ["tech-fingerprint-001", "osint-methodology"],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Read-only HTTP header and status probe; idempotent baseline check.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })
            if not self._is_vector_already_tested(tested_vectors, "katana_execution"):
                selected.append({
                    "name": "Endpoint & Parameter Harvesting",
                    "action": "endpoint_harvesting",
                    "tool": "katana",
                    "description": "Crawl public JS bundles and endpoint surface.",
                    "reason": "ENDPOINT_HARVESTING_REQUIRED",
                    "evidence": [target_name],
                    "knowledge_refs": ["crawl-harvest-001", "hunt-source-leak"],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Read-only GET requests crawling public routes and client-side bundles.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })
            if not self._is_vector_already_tested(tested_vectors, "surface_mapping_and_skill_routing") and not self._is_vector_already_tested(tested_vectors, "nyx-classify_execution"):
                selected.append({
                    "name": "Attack Surface Mapping & Skill Matching",
                    "action": "technology_mapping",
                    "tool": "nyx-classify",
                    "description": "Match detected technologies to specialized NYX security skills.",
                    "reason": "SURFACE_MAPPING_AND_SKILL_ROUTING",
                    "evidence": [target_name] + technologies[:3],
                    "knowledge_refs": ["skill-routing-engine", "tech-matrix"] + rec_skills[:2],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Passive rule-based classification and skill routing in local intelligence memory.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })
            if not self._is_vector_already_tested(tested_vectors, "hypothesis_validation_required"):
                selected.append({
                    "name": "Controlled Vulnerability Triage",
                    "action": "finding_triage",
                    "tool": "nyx-triage",
                    "description": "Validate vulnerability hypotheses against empirical evidence rules.",
                    "reason": "HYPOTHESIS_VALIDATION_REQUIRED",
                    "evidence": hypothesis_ids if hypothesis_ids else ["pending-findings"],
                    "knowledge_refs": ["7-question-gate", "evidence-hygiene"],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Passive quality-gate analysis and reproduction constraint validation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })
        else:
            # Rule 2: Endpoints Present -> Context-Driven Deterministic Selection
            graphql_eps = [e for e in endpoints if "graphql" in str(e).lower()]
            auth_eps = [
                e for e in endpoints
                if any(k in str(e).lower() for k in ["login", "auth", "oauth", "sso", "saml", "signin", "reset-password"])
            ]
            fintech_eps = [
                e for e in graphql_eps
                if any(k in str(e).lower() for k in ["payment", "transfer", "wallet", "checkout", "billing", "withdraw", "refund"])
            ]

            api_eps = [
                e for e in endpoints
                if any(k in str(e).lower() for k in ["/api/", "/rest/", "/v1/", "/v2/", "/users", "/products", "/basket", "/admin", "/feedbacks"])
            ]

            classified_any = False
            if fintech_eps and not self._is_vector_already_tested(tested_vectors, "financial_graphql_mutation_detected") and not self._is_vector_already_tested(tested_vectors, "fintech_graphql_mutation_analysis"):
                classified_any = True
                selected.append({
                    "name": "Financial GraphQL Mutation Analysis",
                    "action": "technology_mapping",
                    "tool": "nyx-classify",
                    "description": "Analyze financial GraphQL operations, alias batching races, and field-level authz.",
                    "reason": "FINANCIAL_GRAPHQL_MUTATION_DETECTED",
                    "evidence": fintech_eps[:5],
                    "knowledge_refs": ["graphql-fintech-mutations", "graphql-node-id-idor", "hunt-fintech-graphql"],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Passive classification and skill mapping against detected financial operations.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })
            if graphql_eps and not self._is_vector_already_tested(tested_vectors, "graphql_surface_detected") and not self._is_vector_already_tested(tested_vectors, "graphql_surface_mapping"):
                classified_any = True
                selected.append({
                    "name": "GraphQL Surface Inspection & Query Mapping",
                    "action": "technology_mapping",
                    "tool": "nyx-classify",
                    "description": "Inspect GraphQL introspection, node ID type confusion, and query depth limits.",
                    "reason": "GRAPHQL_SURFACE_DETECTED",
                    "evidence": graphql_eps[:5],
                    "knowledge_refs": ["graphql-node-id-idor", "hunt-graphql"],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Passive classification and skill mapping against detected GraphQL surface.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })
            if auth_eps and not self._is_vector_already_tested(tested_vectors, "auth_surface_detected") and not self._is_vector_already_tested(tested_vectors, "auth_surface_analysis"):
                classified_any = True
                selected.append({
                    "name": "Authentication & Session Surface Mapping",
                    "action": "technology_mapping",
                    "tool": "nyx-classify",
                    "description": "Map authentication state transitions, OAuth redirect bounds, and session handling.",
                    "reason": "AUTH_SURFACE_DETECTED",
                    "evidence": auth_eps[:5],
                    "knowledge_refs": ["auth-bypass-matrix", "hunt-auth-bypass", "hunt-ato"],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Passive classification and skill mapping against detected authentication surface.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })
            if api_eps and not self._is_vector_already_tested(tested_vectors, "api_surface_detected") and not self._is_vector_already_tested(tested_vectors, "api_surface_analysis"):
                classified_any = True
                selected.append({
                    "name": "REST API & Parameter Surface Analysis",
                    "action": "technology_mapping",
                    "tool": "nyx-classify",
                    "description": "Map API routes, parameter schema variations, and mass assignment vectors.",
                    "reason": "API_SURFACE_DETECTED",
                    "evidence": api_eps[:5],
                    "knowledge_refs": ["hunt-api-misconfig", "hunt-idor"],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Passive classification and skill mapping against detected API surface.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })
            if technologies and not self._is_vector_already_tested(tested_vectors, "known_technology_detected") and not self._is_vector_already_tested(tested_vectors, "technology_surface_mapping"):
                classified_any = True
                selected.append({
                    "name": "Technology-Specific Attack Surface Mapping",
                    "action": "technology_mapping",
                    "tool": "nyx-classify",
                    "description": "Evaluate technology-specific vulnerability maps against detected infrastructure stack.",
                    "reason": "KNOWN_TECHNOLOGY_DETECTED",
                    "evidence": technologies[:5],
                    "knowledge_refs": ["tech-matrix"] + rec_skills[:3],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Passive classification and skill mapping against detected technologies.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })

            if not classified_any and not self._is_vector_already_tested(tested_vectors, "surface_mapping_and_skill_routing") and not self._is_vector_already_tested(tested_vectors, "nyx-classify_execution"):
                selected.append({
                    "name": "Attack Surface Mapping & Skill Matching",
                    "action": "technology_mapping",
                    "tool": "nyx-classify",
                    "description": "Match detected technologies to specialized NYX security skills.",
                    "reason": "SURFACE_MAPPING_AND_SKILL_ROUTING",
                    "evidence": endpoints[:5],
                    "knowledge_refs": ["skill-routing-engine", "tech-matrix"] + rec_skills[:2],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Passive classification and skill mapping against detected endpoints.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })

            # Rule 3: Include step 4 if ANY finding has state == "HYPOTHESIS"
            if has_hypothesis:
                selected.append({
                    "name": "Controlled Vulnerability Triage",
                    "action": "finding_triage",
                    "tool": "nyx-triage",
                    "description": "Validate vulnerability hypotheses against empirical evidence rules.",
                    "reason": "HYPOTHESIS_VALIDATION_REQUIRED",
                    "evidence": hypothesis_ids,
                    "knowledge_refs": ["7-question-gate", "evidence-hygiene"],
                    "impact_class": "NON_DESTRUCTIVE",
                    "impact_justification": "Quality-gate triage and reproduction verification without side effects.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })

        # Rule 4: Add targeted validation sequence steps for explicit vulnerability_type and hypothesis findings
        # Stack awareness helper variables for Rule 4
        tech_list = [str(t).lower() for t in (context.get("technologies") or []) if t]
        all_ep_strs = [e.get("url", "") if isinstance(e, dict) else str(e) for e in endpoints]
        is_php = any("php" in t for t in tech_list) or any(".php" in e.lower() for e in all_ep_strs)
        is_asp = any(t in ("asp.net", "iis", "c#", ".net", "windows") for t in tech_list) or any(".aspx" in e.lower() or ".axd" in e.lower() for e in all_ep_strs)
        is_node = any(t in ("node.js", "express", "next.js", "react", "vue", "angular", "javascript") for t in tech_list)

        def _get_lfi_wordlist() -> str:
            candidates = [
                "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
                "/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
                "/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
                "/usr/share/wordlists/dirb/common.txt",
            ]
            for p in candidates:
                if Path(p).exists():
                    return p
            return "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"

        def _get_content_wordlist() -> str:
            candidates = [
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
                "/usr/share/wordlists/dirb/common.txt",
            ]
            for p in candidates:
                if Path(p).exists():
                    return p
            return "/usr/share/seclists/Discovery/Web-Content/common.txt"

        vuln_targets_to_validate = []
        if vulnerability_type:
            vuln_targets_to_validate.append((str(vulnerability_type), None, target_name))

        for hf in hypothesis_findings_raw:
            if isinstance(hf, dict):
                h_fid = hf.get("finding_id")
                h_vuln = hf.get("vulnerability") or hf.get("title")
                h_ep = hf.get("endpoint") or target_name
                if h_vuln and not any(vt[0] == h_vuln and vt[2] == h_ep for vt in vuln_targets_to_validate):
                    vuln_targets_to_validate.append((str(h_vuln), h_fid, h_ep))

        for v_type, fid_ref, ep_ref in vuln_targets_to_validate:
            v_lower = v_type.lower()
            ev_list = [fid_ref, ep_ref] if fid_ref else [target_name] + endpoints[:2]
            ev_list = [e for e in ev_list if e]

            if "sql" in v_lower:
                # 1. SQL Injection: SQLMap as primary vetted tool + Nuclei secondary
                selected.append({
                    "name": "SQL Injection Validation (SQLMap)",
                    "action": "finding_triage",
                    "tool": "sqlmap",
                    "description": f"Execute automated SQL injection parameter validation using SQLMap against {ep_ref}.",
                    "reason": "SQL_INJECTION_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-sqli", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence executing SQLMap injection probes against {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-u", ep_ref, "--batch"],
                })
                selected.append({
                    "name": "SQL Injection Template Scan (Nuclei)",
                    "action": "finding_triage",
                    "tool": "nuclei",
                    "description": f"Execute automated SQL injection template scan using Nuclei against {ep_ref}.",
                    "reason": "SQL_INJECTION_NUCLEI_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-sqli", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence executing Nuclei SQLi templates against {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-tags", "sqli", "-jsonl"],
                })

            elif "file" in v_lower or "upload" in v_lower or "lfi" in v_lower or "traversal" in v_lower:
                # 2. LFI / Traversal / File Upload: FFUF with stack-aware wordlist + Nuclei template scan
                has_params = "?" in ep_ref and "=" in ep_ref
                fuzz_target = re.sub(r'=([^&]*)', '=FUZZ', ep_ref) if has_params else (ep_ref.rstrip("/") + "/FUZZ")
                lfi_wl = _get_lfi_wordlist()
                match_regex = "root:x:0:0|root:.*:0:0|PHP Warning|fatal error" if is_php else ("root:x:0:0|windows/win.ini|System.Exception" if is_asp else "root:x:0:0|root:.*:0:0")
                
                selected.append({
                    "name": "Local File Inclusion & Traversal Fuzzing (FFUF)",
                    "action": "finding_triage",
                    "tool": "ffuf",
                    "description": f"Execute active path traversal and LFI parameter fuzzing with FFUF using stack-aware wordlists against {ep_ref}.",
                    "reason": "LFI_TRAVERSAL_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-lfi", "hunt-file-upload", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence executing FFUF LFI probes against {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": fuzz_target,
                    "arguments": ["-u", fuzz_target, "-w", lfi_wl, "-mr", match_regex],
                })
                selected.append({
                    "name": "File Inclusion & Upload Template Scan (Nuclei)",
                    "action": "finding_triage",
                    "tool": "nuclei",
                    "description": f"Execute Nuclei template scanning for file upload and traversal vulnerabilities on {ep_ref}.",
                    "reason": "FILE_UPLOAD_NUCLEI_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-file-upload", "hunt-lfi", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence testing file upload boundary filters on {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-tags", "lfi,fileupload,traversal", "-jsonl"],
                })

            elif any(k in v_lower for k in ("discovery", "unlinked", "shadow", "leak", "source")):
                # 3. Directory / Content Discovery: FFUF with stack-appropriate extensions
                content_wl = _get_content_wordlist()
                fuzz_dir_target = ep_ref.rstrip("/") + "/FUZZ" if "FUZZ" not in ep_ref else ep_ref
                ext_str = ".php,.html,.txt" if is_php else (".aspx,.axd,.config" if is_asp else ".js,.json,.html")
                selected.append({
                    "name": "Directory & Unlinked Route Discovery (FFUF)",
                    "action": "finding_triage",
                    "tool": "ffuf",
                    "description": f"Execute stack-aware web directory and API route fuzzing with FFUF on {ep_ref}.",
                    "reason": "CONTENT_DISCOVERY_FUZZING",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-source-leak", "hunt-shadow-api", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active directory fuzzing with FFUF against {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": fuzz_dir_target,
                    "arguments": ["-u", fuzz_dir_target, "-w", content_wl, "-e", ext_str],
                })

            elif "ssrf" in v_lower:
                selected.append({
                    "name": "SSRF Out-of-Band Callback Verification (Nuclei)",
                    "action": "finding_triage",
                    "tool": "nuclei",
                    "description": f"Send non-destructive collaborator token callback probe via Nuclei to confirm external request sink on {ep_ref}.",
                    "reason": "SSRF_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-ssrf", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence executing SSRF callback probes against {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-tags", "ssrf,oast", "-jsonl"],
                })

            elif "graphql" in v_lower:
                selected.append({
                    "name": "GraphQL Query & Mutation Validation (Nuclei)",
                    "action": "finding_triage",
                    "tool": "nuclei",
                    "description": f"Execute automated GraphQL introspection and mutation probes against {ep_ref}.",
                    "reason": "GRAPHQL_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-graphql", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence executing GraphQL security probes against {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-tags", "graphql", "-jsonl"],
                })

            elif "auth" in v_lower or "token" in v_lower or "jwt" in v_lower or "mfa" in v_lower or "recovery" in v_lower:
                selected.append({
                    "name": "Authentication Bypass & Session Verification (Nuclei)",
                    "action": "finding_triage",
                    "tool": "nuclei",
                    "description": f"Evaluate session token invalidation, role-claim tampering, and unauthenticated route boundaries on {ep_ref}.",
                    "reason": "AUTH_BYPASS_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-auth-bypass", "hunt-jwt-crypto", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence testing authentication transitions on {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-tags", "auth,jwt,default-login", "-jsonl"],
                })

            elif "xss" in v_lower:
                selected.append({
                    "name": "Reflected XSS Validation (Nuclei)",
                    "action": "finding_triage",
                    "tool": "nuclei",
                    "description": f"Inject unique alphanumeric canary strings and XSS probes via Nuclei on {ep_ref}.",
                    "reason": "XSS_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-xss", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence executing XSS scanner probes on {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-tags", "xss", "-jsonl"],
                })

            elif "rce" in v_lower or "command" in v_lower:
                selected.append({
                    "name": "Command Injection & RCE Validation (Nuclei)",
                    "action": "finding_triage",
                    "tool": "nuclei",
                    "description": f"Test command separator handling using non-destructive time delay probes on {ep_ref}.",
                    "reason": "COMMAND_INJECTION_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-rce", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence executing command injection probes on {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-tags", "rce,oast", "-jsonl"],
                })

            elif "idor" in v_lower or "bola" in v_lower:
                selected.append({
                    "name": "IDOR Cross-Tenant Boundary Verification",
                    "action": "finding_triage",
                    "tool": "nuclei",
                    "description": f"Execute dual-session probe (Attacker A querying Victim B object identifiers) on {ep_ref}.",
                    "reason": "IDOR_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["hunt-idor", "7-question-gate"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence executing IDOR boundary probes against {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-tags", "idor", "-jsonl"],
                })

            else:
                selected.append({
                    "name": f"{v_type} Hypothesis Validation (Nuclei)",
                    "action": "finding_triage",
                    "tool": "nuclei",
                    "description": f"Execute targeted Nuclei vulnerability scan for {v_type} on {ep_ref}.",
                    "reason": f"{v_type.upper().replace(' ', '_')}_VALIDATION",
                    "evidence": ev_list,
                    "knowledge_refs": ["7-question-gate", "evidence-hygiene"],
                    "impact_class": "DESTRUCTIVE",
                    "impact_justification": f"Active tool-based validation sequence executing probes for {v_type} on {ep_ref}; requires operator confirmation.",
                    "policy_status": "PENDING_POLICY_VALIDATION",
                    "target": ep_ref,
                    "arguments": ["-tags", "cve,misconfig", "-jsonl"],
                })

        # Filter out candidate steps that have already been tested or denied by operator
        candidate_steps: List[Dict[str, Any]] = []
        for s in selected:
            s_tool = str(s.get("tool") or "")
            s_name = str(s.get("name") or "")
            s_action = str(s.get("action") or "")
            s_reason = str(s.get("reason") or "")
            s_target = str(s.get("target") or target_name)
            
            if (
                self._is_vector_already_tested(tested_vectors, f"{s_tool}_execution", s_target) or
                self._is_vector_already_tested(tested_vectors, s_name.lower(), s_target) or
                self._is_vector_already_tested(tested_vectors, s_reason.lower(), s_target) or
                self._is_vector_already_tested(tested_vectors, f"{s_action}_execution", s_target) or
                self._is_vector_already_tested(tested_vectors, s_action.lower(), s_target)
            ):
                continue
            candidate_steps.append(s)

        # Number remaining steps sequentially starting from 1
        numbered_steps = []
        for idx, step_dict in enumerate(candidate_steps, start=1):
            s = dict(step_dict)
            s["step"] = idx
            if "impact_class" not in s:
                s["impact_class"] = "NON_DESTRUCTIVE"
            if "impact_justification" not in s:
                s["impact_justification"] = "Read-only operational check."
            numbered_steps.append(s)

        return numbered_steps

    def create_plan(
        self,
        target: str,
        vulnerability_type: Optional[str] = None,
        provider_name: Optional[str] = None,
        active_permitted: bool = False,
        context_override: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a structured multi-step security mission for a target."""
        context = self.context_engine.get_target_context(target)
        if context_override and isinstance(context_override, dict):
            context.update(context_override)
        if vulnerability_type:
            context["vulnerability_type"] = vulnerability_type

        # 0. Scope & Active Engagement Guard
        if not context.get("in_scope", True):
            return {
                "status": "error",
                "target": target,
                "error": (
                    f"Target '{target}' does not match the active engagement's scope. "
                    f"Run 'nyx engagement init {target}' to start a new engagement for this target, "
                    f"or check 'nyx engagement status' to see the currently active target."
                ),
            }

        # 1. Obtain AI Provider Reasoning with tailored prompt
        vuln_clause = f"Focus particularly on analyzing attack vectors, hypotheses, and validation sequences for: {vulnerability_type}.\n" if vulnerability_type else ""
        custom_prompt = (
            "You are assisting a licensed penetration tester operating within NYX, a "
            "policy-gated security testing tool. This specific target and action have "
            "already been verified as explicitly authorized and in-scope by NYX's own "
            "authorization and scope-enforcement system before this analysis request was "
            "ever made — you are analyzing already-collected, already-permitted "
            "reconnaissance data, not deciding whether to attack anything.\n\n"
            f"Target: {target}\n"
            f"Phase: {context.get('phase', 'DISCOVERY')}\n"
            f"Detected Technologies: {context.get('technologies', [])[:20]}\n"
            f"Harvested Endpoints: {context.get('endpoints', [])[:20]}\n"
            f"Matched Security Skills: {context.get('skills', [])[:15]}\n"
            f"Prior Findings Count: {len(context.get('findings') or context.get('previous_findings', []))}\n"
            f"{vuln_clause}\n"
            "Analyze this specific target context and provide a tailored, high-priority vulnerability research hypothesis and reasoning.\n"
            "Respond ONLY with a valid JSON object (no markdown code blocks, no ```json formatting, no explanation before or after) with exactly these two keys:\n"
            '{\n'
            '  "focus": "<tailored hypothesis or focus area, e.g. SQLi / IDOR / SSRF on specific parameter/endpoint>",\n'
            '  "reasoning": "<2-4 sentence technical hypothesis tied directly to the target, detected technologies, and endpoints>"\n'
            '}'
        )

        analysis = self.ai_manager.analyze(context, prompt=custom_prompt, provider_name=provider_name)
        provider_info = self.ai_manager.get_provider(provider_name).get_info()

        # 2. Build Context-Aware Mission Steps
        raw_steps = self._select_steps(context)

        # 3. Policy Gate Validation
        validated_steps = self.policy_engine.filter_plan_steps(target, raw_steps, active_permitted=active_permitted)

        plan = {
            "target": target,
            "vulnerability_type": vulnerability_type,
            "provider": provider_info.get("name"),
            "phase": context.get("phase", "DISCOVERY"),
            "analysis": analysis.get("analysis", ""),
            "recommended_focus": analysis.get("recommended_focus", ""),
            "steps": validated_steps,
            "total_steps": len(validated_steps),
            "valid": all(s.get("permitted", False) for s in validated_steps),
        }

        # 4. Record decision in AI Memory
        self.memory.record_decision(
            decision_type="MISSION_PLAN",
            details={"target": target, "vulnerability_type": vulnerability_type, "provider": provider_info.get("name"), "valid": plan["valid"]},
        )

        return plan

    def validate_plan(self, plan: Dict[str, Any], active_permitted: bool = False) -> Tuple[bool, str]:
        """Validate an existing mission plan against policy and scope rules."""
        if plan.get("status") == "error":
            return False, plan.get("error", "Plan indicates an error state.")

        target = plan.get("target", "")
        if not target:
            return False, "Plan missing target."

        steps = plan.get("steps", [])
        if not steps:
            return False, "Plan contains no execution steps."

        for step in steps:
            action = step.get("action", "unknown")
            step_target = step.get("target") or target
            ok, err = self.policy_engine.check_action_permitted(action, step_target, active_permitted=active_permitted)
            if not ok:
                return False, f"Step '{step.get('name')}' rejected: {err}"

        return True, "Plan validated successfully under policy gates."

    def execute_step(self, step: Dict[str, Any], target: str, active_permitted: bool = False) -> Dict[str, Any]:
        """Execute a single mission plan step using Application Services."""
        from nyx.application.execution_service import ExecutionService
        from nyx.application.analysis_service import AnalysisService
        from nyx.application.finding_service import FindingService
        from nyx.core.engagement import record_memory
        from nyx.infrastructure.filesystem import _get_eng_dir

        exec_svc = ExecutionService(base_dir=self.base_dir)
        analysis_svc = AnalysisService()
        finding_svc = FindingService(base_dir=self.base_dir)

        tool = step.get("tool")
        step_target = step.get("target") or target
        reason = step.get("reason", tool)

        if tool in ("httpx", "subfinder", "katana", "nuclei", "nmap", "ffuf", "sqlmap", "probe", "vuln_probe"):
            arguments = step.get("arguments") or step.get("args")
            res = exec_svc.run_tool(
                tool,
                step_target,
                arguments=arguments,
                dry_run=not active_permitted,
                active_permitted=active_permitted,
            )
            res_dict = res.to_dict() if hasattr(res, "to_dict") else (res if isinstance(res, dict) else {"success": getattr(res, "success", True)})

            # Record outcome to engagement memory
            is_ok = getattr(res, "success", getattr(res, "is_success", True))
            v_outcome = "tested_success" if is_ok else ("blocked_by_policy" if getattr(res, "code", "") == "EXECUTION_BLOCKED" else "failed_infrastructure")
            try:
                record_memory(mem_type="vector", val=f"{tool}_execution", endpoint=step_target, result=v_outcome, base_dir=self.base_dir)
                if reason and reason != tool:
                    record_memory(mem_type="vector", val=reason.lower(), endpoint=step_target, result=v_outcome, base_dir=self.base_dir)
            except Exception:
                pass

            # Attach evidence and trigger AI validation review for findings
            ev_list = step.get("evidence", [])
            if not isinstance(ev_list, list):
                ev_list = [ev_list]

            target_fids = [str(e) for e in ev_list if str(e).startswith("FH-")]
            if not target_fids:
                try:
                    findings_data = finding_svc.list_findings(base_dir=self.base_dir)
                    all_f = findings_data.get("findings", []) if isinstance(findings_data, dict) else []
                    clean_st = step_target.lower().split("?")[0].rstrip("/")
                    for f in all_f:
                        if f.get("status") in ("HYPOTHESIS", "VALIDATING", "NEEDS VALIDATION"):
                            f_ep = str(f.get("endpoint") or "").lower().split("?")[0].rstrip("/")
                            if f_ep and (f_ep == clean_st or clean_st in f_ep or f_ep in clean_st):
                                fid_val = f.get("finding_id")
                                if fid_val and fid_val not in target_fids:
                                    target_fids.append(fid_val)
                except Exception:
                    pass

            target_fids = target_fids[:5]

            # Only submit to AI review if the adapter/tool actually surfaced matches/vulnerabilities
            raw_vulns = res_dict.get("data", {}).get("vulnerabilities") if isinstance(res_dict.get("data"), dict) else res_dict.get("vulnerabilities", [])
            has_tool_matches = (len(raw_vulns) > 0) if isinstance(raw_vulns, list) else False

            reviews = []
            for fid in target_fids:
                from nyx.core.evidence import add_evidence
                add_evidence(
                    finding_id=fid,
                    ev_type="tool_output",
                    content=json.dumps(res_dict.get("data", {})) or str(res_dict),
                    description=f"Automated tool validation output via {tool}",
                    source=tool,
                    base_dir=self.base_dir,
                )
                if has_tool_matches and (active_permitted or tool in ("ffuf", "nuclei", "sqlmap")):
                    from nyx.core.findings import review_finding_evidence
                    ai_rev = review_finding_evidence(
                        finding_id_or_data=fid,
                        tool_name=tool,
                        tool_output=res_dict,
                        base_dir=self.base_dir,
                    )
                    reviews.append(ai_rev)

            if reviews:
                res_dict["ai_reviews"] = reviews

            return {"step": step.get("step"), "name": step.get("name"), "tool": tool, "result": res_dict}

        elif tool == "nyx-classify":
            ctx = self.context_engine.get_target_context(target)
            endpoints = ctx.get("endpoints", [])

            if endpoints and isinstance(endpoints, list):
                # Prioritize parameterized and high-signal endpoints for classification (up to 200 endpoints)
                param_eps = [e for e in endpoints if "?" in (e.get("url", "") if isinstance(e, dict) else str(e)) or "=" in (e.get("url", "") if isinstance(e, dict) else str(e))]
                other_eps = [e for e in endpoints if e not in param_eps]
                selected_eps = (param_eps + other_eps)[:200]
                classified_results = []
                for ep in selected_eps:
                    ep_str = ep.get("url") if isinstance(ep, dict) else str(ep)
                    c_res = analysis_svc.classify_url(target_url=ep_str)
                    classified_results.append({
                        "url": ep_str,
                        "category": c_res.get("category"),
                        "skills": c_res.get("skills", []),
                        "matches": c_res.get("matches", {}),
                    })
                res = {
                    "status": "success",
                    "classified_count": len(classified_results),
                    "results": classified_results,
                }
            else:
                c_single = analysis_svc.classify_url(target_url=step_target)
                classified_results = [{
                    "url": step_target,
                    "category": c_single.get("category"),
                    "skills": c_single.get("skills", []),
                    "matches": c_single.get("matches", {}),
                }]
                res = c_single

            # BRIDGE: Map classification results to hypothesis findings in findings.json
            created_hypotheses = self._map_classification_to_hypotheses(
                classified_results=classified_results,
                target=target,
            )
            if created_hypotheses:
                res["created_hypotheses"] = created_hypotheses

            try:
                record_memory(mem_type="vector", val=reason.lower(), endpoint=step_target, result="tested_success", base_dir=self.base_dir)
            except Exception:
                pass

            return {"step": step.get("step"), "name": step.get("name"), "tool": tool, "result": res}

        elif tool == "nyx-triage":
            findings_data = finding_svc.list_findings(state="HYPOTHESIS", base_dir=self.base_dir)
            all_hypo = findings_data.get("findings", []) if isinstance(findings_data, dict) else []

            # Filter findings for this target if specified
            target_norm = step_target.lower().replace("https://", "").replace("http://", "").split("/")[0]
            target_findings = []
            for f in all_hypo:
                f_tgt = (f.get("target") or f.get("endpoint") or "").lower()
                if not step_target or target_norm in f_tgt or step_target.lower() in f_tgt:
                    target_findings.append(f)

            if not target_findings:
                try:
                    record_memory(mem_type="vector", val="hypothesis_validation_required", endpoint=step_target, result="tested_skipped", base_dir=self.base_dir)
                except Exception:
                    pass
                return {
                    "step": step.get("step"),
                    "name": step.get("name"),
                    "tool": tool,
                    "result": {
                        "status": "skipped",
                        "reason": "No pending findings to triage for this target.",
                    },
                }
            else:
                triaged_list = []
                d = _get_eng_dir(create=False, base_dir=self.base_dir)
                for f in target_findings:
                    fid = f.get("finding_id")
                    finding_file = str(d / "findings" / fid / "finding.json")

                    t_res = finding_svc.triage(finding_file=finding_file)
                    triaged_list.append({
                        "finding_id": fid,
                        "triage": t_res,
                    })

                    # Record finding triage result in tested vectors
                    t_verdict = (t_res.get("verdict") or t_res.get("status") or "").upper()
                    f_outcome = "tested_success" if t_verdict in ("PASS", "PASSED", "CONFIRMED") else ("tested_negative" if t_verdict in ("KILL", "REJECTED") else "tested_inconclusive")
                    try:
                        record_memory(mem_type="vector", val=f"triage_{fid}", endpoint=f.get("endpoint", step_target), result=f_outcome, base_dir=self.base_dir)
                    except Exception:
                        pass

                try:
                    record_memory(mem_type="vector", val="hypothesis_validation_required", endpoint=step_target, result="tested_success", base_dir=self.base_dir)
                except Exception:
                    pass

                return {
                    "step": step.get("step"),
                    "name": step.get("name"),
                    "tool": tool,
                    "result": {
                        "status": "success",
                        "triaged_count": len(triaged_list),
                        "findings": triaged_list,
                    },
                }

        elif tool == "nyx-validate":
            if not active_permitted:
                try:
                    from nyx.core.engagement import add_memory
                    add_memory(type_="vector", value=reason.lower(), endpoint=step_target, result="manual_action_required", base_dir=self.base_dir)
                except Exception:
                    pass
                return {
                    "step": step.get("step"),
                    "name": step.get("name"),
                    "tool": tool,
                    "result": {
                        "status": "manual_action_required",
                        "message": "No automated probe-execution capability exists for this vulnerability class yet. Manual verification required.",
                    },
                }

            # Tool-based active validation orchestrating real tools (nuclei, sqlmap)
            from nyx.execution.engine import ExecutionEngine
            from nyx.execution.adapters.nuclei import get_nuclei_template_for_vuln
            from nyx.core.evidence import add_evidence

            eng = ExecutionEngine(base_dir=self.base_dir)
            v_reason = reason.lower()
            v_name = str(step.get("name", "")).lower()

            if "sql" in v_reason or "sql" in v_name:
                tool_to_use = "sqlmap"
                tool_args = ["-u", step_target, "--batch"]
            else:
                tool_to_use = "nuclei"
                tmpl_info = get_nuclei_template_for_vuln(reason) or get_nuclei_template_for_vuln(step.get("name", ""))
                if tmpl_info and tmpl_info.get("tags"):
                    tool_args = ["-tags", tmpl_info["tags"], "-jsonl"]
                elif tmpl_info and tmpl_info.get("template_id"):
                    tool_args = ["-t", tmpl_info["template_id"], "-jsonl"]
                else:
                    tool_args = ["-jsonl"]

            exec_res = eng.execute(
                tool_name=tool_to_use,
                target=step_target,
                arguments=tool_args,
                active_permitted=active_permitted,
            )

            if exec_res.status == "BLOCKED":
                return {
                    "step": step.get("step"),
                    "name": step.get("name"),
                    "tool": tool,
                    "result": {
                        "status": "blocked_by_policy",
                        "reason": exec_res.error_message or exec_res.stderr,
                    },
                }

            # Attach evidence for hypothesis findings
            ev_records = []
            findings_ev = step.get("evidence", [])
            if not isinstance(findings_ev, list):
                findings_ev = [findings_ev]

            reviews = []
            for ev_item in findings_ev:
                if str(ev_item).startswith("FH-"):
                    fid = str(ev_item)
                    ev_res = add_evidence(
                        finding_id=fid,
                        ev_type="tool_output",
                        content=exec_res.stdout or exec_res.stderr or json.dumps(exec_res.metadata or {}),
                        description=f"Automated tool validation output via {tool_to_use}",
                        source=tool_to_use,
                        base_dir=self.base_dir,
                    )
                    if isinstance(ev_res, dict) and ev_res.get("evidence_id"):
                        ev_records.append(ev_res.get("evidence_id"))

                    from nyx.core.findings import review_finding_evidence
                    ai_rev = review_finding_evidence(
                        finding_id_or_data=fid,
                        tool_name=tool_to_use,
                        tool_output=exec_res.stdout or exec_res.stderr or exec_res.metadata,
                        base_dir=self.base_dir,
                    )
                    reviews.append(ai_rev)

            raw_findings = []
            if isinstance(exec_res.metadata, dict):
                raw_findings = exec_res.metadata.get("vulnerabilities", [])

            t_outcome = "tested_success" if (exec_res.exit_code == 0 and len(raw_findings) > 0) else "tested_negative"
            try:
                from nyx.core.engagement import add_memory
                add_memory(type_="vector", value=reason.lower(), endpoint=step_target, result=t_outcome, base_dir=self.base_dir)
            except Exception:
                pass

            return {
                "step": step.get("step"),
                "name": step.get("name"),
                "tool": tool,
                "result": {
                    "status": "success" if exec_res.status in ("COMPLETED", "SUCCESS") else exec_res.status.lower(),
                    "tool_used": tool_to_use,
                    "execution_id": exec_res.execution_id,
                    "evidence_ids": ev_records,
                    "raw_findings": raw_findings,
                    "stdout": exec_res.stdout,
                    "stderr": exec_res.stderr,
                },
            }
        else:
            raise ValueError(f"Unknown or unsupported tool '{tool}' in mission plan step {step.get('step')}.")

    def execute_plan(self, plan: Dict[str, Any], active_permitted: bool = False) -> Dict[str, Any]:
        """Execute a validated mission plan using Application Services."""
        valid, msg = self.validate_plan(plan, active_permitted=active_permitted)
        if not valid:
            return {"status": "error", "error": msg, "executed_steps": 0}

        results = []
        target = plan.get("target", "")

        for step in plan.get("steps", []):
            step_result = self.execute_step(step, target, active_permitted=active_permitted)
            results.append(step_result)

        return {
            "status": "success",
            "target": target,
            "executed_steps": len(results),
            "step_results": results,
        }

    def run_autonomous_loop(
        self,
        target: str,
        provider_name: Optional[str] = None,
        active_permitted: bool = False,
        max_iterations: int = 15,
    ) -> Dict[str, Any]:
        """Execute autonomous mission loop with AI-guided candidate selection, policy gates, and pause-on-destructive safety."""
        import re
        iterations: List[Dict[str, Any]] = []

        # 0. Initial Context & Scope Check
        init_context = self.context_engine.get_target_context(target)
        if not init_context.get("in_scope", True):
            return {
                "status": "error",
                "error": "out of scope",
                "target": target,
                "iterations": iterations,
            }

        # 0.b. Auto-bootstrap reconnaissance if target context shows zero endpoints mapped
        logger.info("[MISSION] Starting autonomous loop for target: %s (max_iterations: %d, active_permitted: %s)", target, max_iterations, active_permitted)

        # 0. Context Bootstrap Gate: If zero endpoints are mapped, auto-bootstrap recon
        initial_ctx = self.context_engine.get_target_context(target)
        initial_eps = initial_ctx.get("endpoints") or []
        recon_bootstrapped = False

        if len(initial_eps) == 0:
            recon_step = {
                "name": "Attack Surface Reconnaissance Bootstrap",
                "action": "passive_recon",
                "tool": "nyx-recon",
                "target": target,
                "impact_class": "NON_DESTRUCTIVE",
                "impact_justification": "Passive reconnaissance and endpoint discovery to map attack surface.",
            }
            validated_recon = self.policy_engine.filter_plan_steps(target, [recon_step], active_permitted=active_permitted)
            if validated_recon and validated_recon[0].get("permitted", False):
                try:
                    logger.info("[MISSION] Zero endpoints mapped — auto-bootstrapping reconnaissance for %s...", target)
                    from nyx.application.recon_service import ReconService
                    recon_svc = ReconService(base_dir=self.base_dir)
                    recon_svc.run_recon(target=target)
                    recon_bootstrapped = True
                except Exception:
                    pass

        for iteration_idx in range(1, max_iterations + 1):
            # 1.a. Re-fetch context fresh every iteration
            context = self.context_engine.get_target_context(target)

            # 1.b. Scope check
            if not context.get("in_scope", True):
                logger.error("[ERROR] Target %s is outside engagement scope boundaries.", target)
                return {
                    "status": "error",
                    "error": "out of scope",
                    "target": target,
                    "iterations": iterations,
                    "recon_bootstrapped": recon_bootstrapped,
                }

            # 1.c. Candidate generation & policy filtering
            candidates = self._select_steps(context)
            validated = self.policy_engine.filter_plan_steps(target, candidates, active_permitted=active_permitted)
            logger.info("[MISSION] Iteration %d/%d — Evaluated %d candidate step(s) (%d policy-permitted)", iteration_idx, max_iterations, len(candidates), len(validated))

            # 1.d. Check if remaining candidates is empty
            if not validated:
                tested_vectors = context.get("tested_vectors") or []
                tested_count = len(tested_vectors)
                is_dedup = tested_count > 0 and len(iterations) == 0
                
                if len(iterations) > 0:
                    msg = "Autonomous Mission Loop Complete: All candidate vectors evaluated without violations."
                elif is_dedup:
                    msg = f"All candidate vectors already evaluated in a prior run — {tested_count} vector{'s' if tested_count != 1 else ''} previously tested."
                else:
                    msg = "No candidate vectors found for this target."

                logger.info("[DONE] %s", msg)
                return {
                    "status": "complete",
                    "reason": "no_remaining_candidates",
                    "target": target,
                    "iterations": iterations,
                    "tested_vectors_count": tested_count,
                    "is_dedup": is_dedup,
                    "recon_bootstrapped": recon_bootstrapped,
                    "endpoints_count": len(context.get("endpoints", [])),
                    "message": msg,
                }

            # 1.e. AI-Guided Candidate Selection (selecting strictly FROM validated list)
            candidates_summary = [
                {
                    "index": idx,
                    "name": step.get("name"),
                    "tool": step.get("tool"),
                    "reason": step.get("reason"),
                    "impact_class": step.get("impact_class"),
                    "description": step.get("description"),
                }
                for idx, step in enumerate(validated)
            ]

            prior_history_summary = [
                {
                    "iteration": it.get("iteration"),
                    "tool": it.get("step", {}).get("tool"),
                    "name": it.get("step", {}).get("name"),
                    "status": (it.get("result", {}).get("status") if isinstance(it.get("result"), dict) else "completed"),
                }
                for it in iterations
            ]

            # Tier 1 Skill Summary Injection (< 500 tokens)
            from nyx.core.skills import get_candidates_skill_summaries, get_skill_content
            playbook_reference_block = get_candidates_skill_summaries(validated, max_tokens=500)
            playbook_section = ""
            if playbook_reference_block:
                playbook_section = f"Reference Playbooks (Methodology & Gate Guidance):\n{playbook_reference_block}\n\n"

            decision_prompt = (
                "You are an AI decision engine for NYX, operating within an authorized engagement.\n"
                f"Target: {target}\n"
                f"Current Phase: {context.get('phase', 'DISCOVERY')}\n"
                f"Detected Technologies: {context.get('technologies', [])[:15]}\n"
                f"Harvested Endpoints Count: {len(context.get('endpoints', []))}\n"
                f"Prior Iterations History:\n{json.dumps(prior_history_summary, indent=2)}\n\n"
                f"{playbook_section}"
                f"Policy-Validated Candidate Steps:\n{json.dumps(candidates_summary, indent=2)}\n\n"
                "Select the most strategic candidate step to execute next (by candidate index), or signal escalation/skip.\n"
                "Ground your choice and reasoning in the provided playbook methodology and verification gates.\n"
                "Respond ONLY with a valid JSON object with these keys:\n"
                "{\n"
                f'  "selected_index": <integer from 0 to {len(validated) - 1}>,\n'
                '  "decision": "proceed" | "escalate" | "skip",\n'
                '  "reasoning": "<concise explanation referencing playbook methodology for this selection>"\n'
                "}"
            )

            augmented_context = {
                **context,
                "validated_candidates": candidates_summary,
                "prior_iterations": prior_history_summary,
                "playbook_references": playbook_reference_block,
            }

            ai_reasoning = self.ai_manager.analyze(
                augmented_context,
                prompt=decision_prompt,
                provider_name=provider_name,
            )

            # SAFETY REQUIREMENT: Parse chosen candidate index; fail-closed if AI is unavailable / error / 429 / unparseable
            chosen_idx = None
            ai_degraded = False
            degradation_reason = None
            parsed_json = None
            candidate_idx_val = None

            if isinstance(ai_reasoning, dict):
                is_error_status = (
                    ai_reasoning.get("status") == "error"
                    or ai_reasoning.get("error_type") is not None
                    or ai_reasoning.get("success") is False
                    or "error" in ai_reasoning
                    or ai_reasoning.get("recommended_focus") == "AI analysis unavailable"
                    or "AI analysis unavailable" in str(ai_reasoning.get("analysis") or "")
                )
                if is_error_status:
                    ai_degraded = True
                    raw_err = (
                        ai_reasoning.get("error")
                        or ai_reasoning.get("analysis")
                        or ai_reasoning.get("message")
                        or ai_reasoning.get("error_type")
                        or "AI provider unavailable"
                    )
                    degradation_reason = str(raw_err)
                    if "429" in degradation_reason or "rate limit" in degradation_reason.lower():
                        degradation_reason = f"Groq rate limit reached (HTTP 429): {degradation_reason}"
                else:
                    candidate_idx_val = ai_reasoning.get("selected_index")

                    # If the provider returned raw JSON within the analysis text, attempt regex parsing
                    if candidate_idx_val is None or "decision" not in ai_reasoning:
                        raw_text = str(ai_reasoning.get("analysis") or "")
                        try:
                            m = re.search(r'\{.*\}', raw_text, re.DOTALL)
                            if m:
                                parsed = json.loads(m.group(0))
                                if isinstance(parsed, dict):
                                    parsed_json = parsed
                                    if candidate_idx_val is None:
                                        candidate_idx_val = parsed_json.get("selected_index")
                        except Exception:
                            pass

                    if isinstance(candidate_idx_val, int) and 0 <= candidate_idx_val < len(validated):
                        chosen_idx = candidate_idx_val
                    elif isinstance(candidate_idx_val, str) and candidate_idx_val.strip().isdigit():
                        parsed_int = int(candidate_idx_val.strip())
                        if 0 <= parsed_int < len(validated):
                            chosen_idx = parsed_int
                    else:
                        ai_degraded = True
                        degradation_reason = f"Unparseable AI decision response: {str(ai_reasoning.get('analysis') or ai_reasoning)[:300]}"
            else:
                ai_degraded = True
                degradation_reason = f"AI provider returned non-dict response: {str(ai_reasoning)[:300]}"

            # FAIL-CLOSED BEHAVIOR: Stop loop immediately when AI is unavailable
            if ai_degraded:
                logger.error(
                    "[AI-UNAVAILABLE] Autonomous mission halted at iteration %d — AI provider unavailable: %s",
                    iteration_idx,
                    degradation_reason,
                )
                # Keep prior successful iterations & findings intact; halt execution immediately
                return {
                    "status": "ai_unavailable",
                    "reason": "ai_provider_failure",
                    "error": degradation_reason,
                    "target": target,
                    "iteration_halted": iteration_idx,
                    "iterations": iterations,
                    "recon_bootstrapped": recon_bootstrapped,
                    "endpoints_count": len(context.get("endpoints", [])),
                    "ai_degraded": True,
                    "degradation_reason": degradation_reason,
                    "message": f"AI provider unavailable: {degradation_reason}. Autonomous mission halted. No new findings generated.",
                }

            next_step = validated[chosen_idx]
            next_step["ai_degraded"] = False
            next_step["degradation_reason"] = None

            # Tier 2 Skill Body Injection (selected candidate only, <= 1500 tokens)
            k_refs = next_step.get("knowledge_refs") or []
            selected_skill_content = None
            for ref in k_refs:
                content = get_skill_content(ref, max_tokens=1500)
                if content:
                    selected_skill_content = content
                    break

            if selected_skill_content:
                next_step["playbook_guidance"] = selected_skill_content

            logger.info("[MISSION] Selected candidate #%d: '%s' [%s] using '%s' (Reason: %s, AI Degraded: %s)", chosen_idx, next_step.get("name"), next_step.get("impact_class"), next_step.get("tool"), next_step.get("reason"), ai_degraded)

            # 1.f. Pause on DESTRUCTIVE step (do NOT execute)
            if next_step.get("impact_class") == "DESTRUCTIVE":
                logger.warning("[PAUSED] Autonomous loop paused for operator approval on DESTRUCTIVE step: '%s' (Tool: %s, Target: %s)", next_step.get("name"), next_step.get("tool"), next_step.get("target") or target)
                try:
                    from nyx.agent.approval import ApprovalSystem
                    import uuid
                    app_sys = ApprovalSystem(base_dir=self.base_dir)
                    act_id = f"ACT-{uuid.uuid4().hex[:6].upper()}"
                    app_sys.submit_for_approval({
                        "action_id": act_id,
                        "target": next_step.get("target") or target,
                        "action": next_step.get("action", "validate"),
                        "reason": next_step.get("reason", "DESTRUCTIVE_VALIDATION"),
                        "tool_name": next_step.get("tool", "nyx-validate"),
                        "risk": "High",
                        "impact_class": next_step.get("impact_class", "DESTRUCTIVE"),
                        "impact_justification": next_step.get("impact_justification", ""),
                        "step": next_step,
                    })
                except Exception:
                    pass
                return {
                    "status": "paused_for_approval",
                    "pending_step": next_step,
                    "target": target,
                    "iterations": iterations,
                    "recon_bootstrapped": recon_bootstrapped,
                    "ai_degraded": ai_degraded,
                    "degradation_reason": degradation_reason,
                }

            # 1.g. Stop if policy blocked
            if next_step.get("permitted") is False:
                logger.error("[ERROR] Step '%s' blocked by safety policy: %s", next_step.get("name"), next_step.get("policy_reason", "Not permitted"))
                return {
                    "status": "blocked",
                    "blocked_step": next_step,
                    "target": target,
                    "iterations": iterations,
                    "recon_bootstrapped": recon_bootstrapped,
                    "ai_degraded": ai_degraded,
                    "degradation_reason": degradation_reason,
                }

            # Decision branching (proceed | escalate | skip)
            decision_val = "proceed"
            if isinstance(ai_reasoning, dict):
                d_raw = ai_reasoning.get("decision")
                if d_raw is None and parsed_json and isinstance(parsed_json, dict):
                    d_raw = parsed_json.get("decision")
                if isinstance(d_raw, str):
                    d_clean = d_raw.strip().lower()
                    if d_clean in ("skip", "escalate", "proceed"):
                        decision_val = d_clean

            if decision_val == "escalate":
                logger.warning("[ESCALATED] AI decision requested operator escalation on step: '%s'", next_step.get("name"))
                return {
                    "status": "escalated",
                    "escalated_step": next_step,
                    "reasoning": ai_reasoning,
                    "target": target,
                    "iterations": iterations,
                    "recon_bootstrapped": recon_bootstrapped,
                    "ai_degraded": ai_degraded,
                    "degradation_reason": degradation_reason,
                }
            elif decision_val == "skip":
                logger.info("[SKIP] AI decision skipped step: '%s'", next_step.get("name"))
                try:
                    from nyx.core.engagement import add_memory
                    s_target = next_step.get("target") or target
                    v_key = next_step.get("reason", "").lower() or f"{next_step.get('tool')}_execution"
                    add_memory(type_="vector", value=v_key, endpoint=s_target, result="tested_skipped", base_dir=self.base_dir)
                except Exception:
                    pass
                iterations.append({
                    "iteration": iteration_idx,
                    "step": next_step,
                    "ai_reasoning": ai_reasoning,
                    "ai_degraded": ai_degraded,
                    "degradation_reason": degradation_reason,
                    "result": {
                        "status": "skipped",
                        "reason": "AI decision signalled skip",
                    },
                })
                continue

            # 1.h. Execute step and record iteration
            logger.info("[MISSION] Executing step '%s' on %s via tool '%s'...", next_step.get("name"), next_step.get("target") or target, next_step.get("tool"))
            result = self.execute_step(next_step, target, active_permitted=active_permitted)
            step_status = result.get("result", {}).get("status") if isinstance(result, dict) else "completed"
            logger.info("[DONE] Step '%s' complete — status: %s", next_step.get("name"), step_status)
            iterations.append({
                "iteration": iteration_idx,
                "step": next_step,
                "ai_reasoning": ai_reasoning,
                "ai_degraded": ai_degraded,
                "degradation_reason": degradation_reason,
                "result": result,
            })

        # 2. Max iterations reached without terminal state
        logger.info("[DONE] Autonomous loop reached maximum iteration limit (%d)", max_iterations)
        any_degraded = any(it.get("ai_degraded") for it in iterations)
        deg_reason = next((it.get("degradation_reason") for it in iterations if it.get("degradation_reason")), None)
        return {
            "status": "max_iterations_reached",
            "target": target,
            "iterations": iterations,
            "recon_bootstrapped": recon_bootstrapped,
            "endpoints_count": len(context.get("endpoints", [])),
            "ai_degraded": any_degraded,
            "degradation_reason": deg_reason,
        }
