"""
NYX Mission Reasoning Engine & Planner
Converts AI decisions into structured, policy-validated NYX security missions.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from nyx.ai.context import ContextEngine
from nyx.ai.manager import AIManager
from nyx.ai.memory import AIMemory
from nyx.security.ai_policy import AIPolicyEngine


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
            v = tv.get("vector") or tv.get("name") or ""
            res = tv.get("result") or tv.get("status") or ""
            ep = tv.get("endpoint")
            if v == vector_name:
                if endpoint and ep and endpoint != ep:
                    continue
                if res in ("tested_negative", "tested_success", "blocked_by_policy"):
                    return True
        return False

    def _select_steps(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Select and renumber mission plan steps based on target intelligence context, tested vectors, and knowledge."""
        target_name = context.get("target") or context.get("domain") or "target"
        endpoints = context.get("endpoints") or []
        technologies = [str(t) for t in (context.get("technologies") or []) if t]
        findings = context.get("findings") or context.get("previous_findings") or []
        tested_vectors = context.get("tested_vectors") or []
        relevant_k = context.get("relevant_knowledge") or {}
        rec_skills = relevant_k.get("recommended_skills") or ["skill-routing-engine"]

        hypothesis_findings = [
            f.get("finding_id", "hyp-001")
            for f in findings
            if isinstance(f, dict) and (f.get("state") or f.get("status") or "").upper() == "HYPOTHESIS"
        ]
        has_hypothesis = len(hypothesis_findings) > 0

        selected: List[Dict[str, Any]] = []

        if not endpoints:
            # Rule 1: No Endpoints (Full Discovery Phase Pipeline)
            selected.append({
                "name": "Technology Fingerprinting",
                "action": "passive_recon",
                "tool": "httpx",
                "description": "Probe live host, HTTP headers, titles, and technology stack.",
                "reason": "INITIAL_HOST_DISCOVERY",
                "evidence": [target_name],
                "knowledge_refs": ["tech-fingerprint-001", "osint-methodology"],
                "policy_status": "PENDING_POLICY_VALIDATION",
            })
            selected.append({
                "name": "Endpoint & Parameter Harvesting",
                "action": "endpoint_harvesting",
                "tool": "katana",
                "description": "Crawl public JS bundles and endpoint surface.",
                "reason": "ENDPOINT_HARVESTING_REQUIRED",
                "evidence": [target_name],
                "knowledge_refs": ["crawl-harvest-001", "hunt-source-leak"],
                "policy_status": "PENDING_POLICY_VALIDATION",
            })
            selected.append({
                "name": "Attack Surface Mapping & Skill Matching",
                "action": "technology_mapping",
                "tool": "nyx-classify",
                "description": "Match detected technologies to specialized NYX security skills.",
                "reason": "SURFACE_MAPPING_AND_SKILL_ROUTING",
                "evidence": [target_name] + technologies[:3],
                "knowledge_refs": ["skill-routing-engine", "tech-matrix"] + rec_skills[:2],
                "policy_status": "PENDING_POLICY_VALIDATION",
            })
            selected.append({
                "name": "Controlled Vulnerability Triage",
                "action": "finding_triage",
                "tool": "nyx-triage",
                "description": "Validate vulnerability hypotheses against empirical evidence rules.",
                "reason": "HYPOTHESIS_VALIDATION_REQUIRED",
                "evidence": hypothesis_findings if hypothesis_findings else ["pending-findings"],
                "knowledge_refs": ["7-question-gate", "evidence-hygiene"],
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

            classify_reason = "SURFACE_MAPPING_AND_SKILL_ROUTING"
            classify_evidence = endpoints[:5]
            classify_refs = ["skill-routing-engine", "tech-matrix"] + rec_skills[:2]
            classify_desc = "Match detected technologies to specialized NYX security skills."

            if fintech_eps and not self._is_vector_already_tested(tested_vectors, "fintech_graphql_mutation_analysis"):
                classify_reason = "FINANCIAL_GRAPHQL_MUTATION_DETECTED"
                classify_evidence = fintech_eps[:5]
                classify_refs = ["graphql-fintech-mutations", "graphql-node-id-idor", "hunt-fintech-graphql"]
                classify_desc = "Analyze financial GraphQL operations, alias batching races, and field-level authz."
            elif graphql_eps and not self._is_vector_already_tested(tested_vectors, "graphql_surface_mapping"):
                classify_reason = "GRAPHQL_SURFACE_DETECTED"
                classify_evidence = graphql_eps[:5]
                classify_refs = ["graphql-node-id-idor", "hunt-graphql"]
                classify_desc = "Inspect GraphQL introspection, node ID type confusion, and query depth limits."
            elif auth_eps and not self._is_vector_already_tested(tested_vectors, "auth_surface_analysis"):
                classify_reason = "AUTH_SURFACE_DETECTED"
                classify_evidence = auth_eps[:5]
                classify_refs = ["auth-bypass-matrix", "hunt-auth-bypass", "hunt-ato"]
                classify_desc = "Map authentication state transitions, OAuth redirect bounds, and session handling."
            elif technologies and not self._is_vector_already_tested(tested_vectors, "technology_surface_mapping"):
                classify_reason = "KNOWN_TECHNOLOGY_DETECTED"
                classify_evidence = technologies[:5]
                classify_refs = ["tech-matrix"] + rec_skills[:3]
                classify_desc = "Evaluate technology-specific vulnerability maps against detected infrastructure stack."

            selected.append({
                "name": "Attack Surface Mapping & Skill Matching",
                "action": "technology_mapping",
                "tool": "nyx-classify",
                "description": classify_desc,
                "reason": classify_reason,
                "evidence": classify_evidence,
                "knowledge_refs": classify_refs,
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
                    "evidence": hypothesis_findings,
                    "knowledge_refs": ["7-question-gate", "evidence-hygiene"],
                    "policy_status": "PENDING_POLICY_VALIDATION",
                })

        # Number remaining steps sequentially starting from 1
        numbered_steps = []
        for idx, step_dict in enumerate(selected, start=1):
            s = dict(step_dict)
            s["step"] = idx
            numbered_steps.append(s)

        return numbered_steps

    def create_plan(
        self,
        target: str,
        provider_name: Optional[str] = None,
        active_permitted: bool = False,
    ) -> Dict[str, Any]:
        """Generate a structured multi-step security mission for a target."""
        context = self.context_engine.get_target_context(target)

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

        # 1. Obtain AI Provider Reasoning
        analysis = self.ai_manager.analyze(context, provider_name=provider_name)
        provider_info = self.ai_manager.get_provider(provider_name).get_info()

        # 2. Build Context-Aware Mission Steps
        raw_steps = self._select_steps(context)

        # 3. Policy Gate Validation
        validated_steps = self.policy_engine.filter_plan_steps(target, raw_steps, active_permitted=active_permitted)

        plan = {
            "target": target,
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
            details={"target": target, "provider": provider_info.get("name"), "valid": plan["valid"]},
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

    def execute_plan(self, plan: Dict[str, Any], active_permitted: bool = False) -> Dict[str, Any]:
        """Execute a validated mission plan using Application Services."""
        valid, msg = self.validate_plan(plan, active_permitted=active_permitted)
        if not valid:
            return {"status": "error", "error": msg, "executed_steps": 0}

        results = []
        target = plan.get("target", "")
        from nyx.application.execution_service import ExecutionService
        from nyx.application.analysis_service import AnalysisService
        from nyx.application.finding_service import FindingService
        from nyx.core.engagement import record_memory
        from nyx.infrastructure.filesystem import _get_eng_dir

        exec_svc = ExecutionService(base_dir=self.base_dir)
        analysis_svc = AnalysisService()
        finding_svc = FindingService(base_dir=self.base_dir)

        for step in plan.get("steps", []):
            tool = step.get("tool")
            step_target = step.get("target") or target
            reason = step.get("reason", tool)

            if tool in ("httpx", "subfinder", "katana", "nuclei", "nmap"):
                res = exec_svc.run_tool(tool, step_target, dry_run=not active_permitted, active_permitted=active_permitted)
                res_dict = res.to_dict()
                results.append({"step": step.get("step"), "name": step.get("name"), "tool": tool, "result": res_dict})

                # Record outcome to engagement memory
                v_outcome = "tested_success" if res.is_success else ("blocked_by_policy" if res.error_code == "EXECUTION_BLOCKED" else "failed_infrastructure")
                try:
                    record_memory(mem_type="vector", val=f"{tool}_execution", endpoint=step_target, result=v_outcome, base_dir=self.base_dir)
                except Exception:
                    pass

            elif tool == "nyx-classify":
                ctx = self.context_engine.get_target_context(target)
                endpoints = ctx.get("endpoints", [])

                if endpoints and isinstance(endpoints, list):
                    selected_eps = endpoints[:5]
                    classified_results = []
                    for ep in selected_eps:
                        c_res = analysis_svc.classify_url(target_url=ep)
                        classified_results.append({
                            "url": ep,
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
                    res = analysis_svc.classify_url(target_url=step_target)

                results.append({"step": step.get("step"), "name": step.get("name"), "tool": tool, "result": res})
                try:
                    record_memory(mem_type="vector", val=reason.lower(), endpoint=step_target, result="tested_success", base_dir=self.base_dir)
                except Exception:
                    pass

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
                    results.append({
                        "step": step.get("step"),
                        "name": step.get("name"),
                        "tool": tool,
                        "result": {
                            "status": "skipped",
                            "reason": "No pending findings to triage for this target.",
                        },
                    })
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

                    results.append({
                        "step": step.get("step"),
                        "name": step.get("name"),
                        "tool": tool,
                        "result": {
                            "status": "success",
                            "triaged_count": len(triaged_list),
                            "findings": triaged_list,
                        },
                    })
            else:
                raise ValueError(f"Unknown or unsupported tool '{tool}' in mission plan step {step.get('step')}.")

        return {
            "status": "success",
            "target": target,
            "executed_steps": len(results),
            "step_results": results,
        }
