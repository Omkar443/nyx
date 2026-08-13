#!/usr/bin/env python3
"""
Phase 7.0 — NYX Knowledge & Skill Intelligence Layer Test Suite
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

def run_cli(args, cwd):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    cmd = [sys.executable, "-m", "nyx_cli.cli"] + args
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr

def run_phase70_tests():
    test_dir = REPO_ROOT / "test-phase70-workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 7.0 NYX KNOWLEDGE & SKILL INTELLIGENCE TESTS")
    print("==================================================")

    # 1. Knowledge Directory Exists
    k_dir = REPO_ROOT / "knowledge"
    results["1_knowledge_dir_exists"] = (
        k_dir.exists() and (k_dir / "technologies").exists() and (k_dir / "vulnerabilities").exists()
    )

    # 2. Knowledge Loader Imports Correctly
    try:
        from nyx.core.knowledge import load_knowledge, load_technology, load_vulnerability, search_knowledge
        results["2_knowledge_loader_imports"] = True
    except Exception as e:
        print(f"Knowledge import error: {e}")
        results["2_knowledge_loader_imports"] = False

    # 3. Technology YAML Loads
    asp_tech = load_technology("ASP.NET")
    results["3_technology_yaml_loads"] = (
        isinstance(asp_tech, dict) and
        asp_tech.get("technology", {}).get("name") == "ASP.NET" and
        "hunt-aspnet" in asp_tech.get("related_skills", [])
    )

    # 4. Vulnerability YAML Loads
    auth_vuln = load_vulnerability("auth_bypass")
    results["4_vulnerability_yaml_loads"] = (
        isinstance(auth_vuln, dict) and
        auth_vuln.get("vulnerability", {}).get("name") == "Authentication Bypass"
    )

    # 5. Skill Router Works
    from nyx.core.router import recommend_skills
    rec = recommend_skills("http://example.com/login.aspx", technology="ASP.NET")
    results["5_skill_router_works"] = isinstance(rec, dict) and len(rec.get("recommended_skills", [])) > 0

    # 6. ASP.NET Login Endpoint Recommendations
    rec_asp = recommend_skills("http://testaspnet.vulnweb.com/login.aspx", technology="ASP.NET")
    results["6_aspnet_login_recommendations"] = (
        rec_asp.get("priority") == "HIGH" and
        "hunt-aspnet" in rec_asp.get("recommended_skills", []) and
        "hunt-auth-bypass" in rec_asp.get("recommended_skills", [])
    )

    # 7. Attack Surface Graph Builds
    from nyx.core.surface import build_attack_surface_graph
    graph = build_attack_surface_graph("testaspnet.vulnweb.com", endpoints=["/login.aspx"], technologies=["ASP.NET"])
    results["7_attack_surface_graph_builds"] = (
        isinstance(graph, dict) and
        graph.get("target") == "testaspnet.vulnweb.com" and
        len(graph.get("nodes", [])) >= 3
    )

    # 8. Analysis Context Generation Works
    from nyx.core.analysis import decision_context
    ctx = decision_context(target="testaspnet.vulnweb.com", url="http://testaspnet.vulnweb.com/login.aspx")
    results["8_analysis_context_generation"] = (
        isinstance(ctx, dict) and
        ctx.get("target") == "testaspnet.vulnweb.com" and
        "graph" in ctx
    )

    # 9. CLI Commands Work
    run_cli(["engagement", "init", "testaspnet.vulnweb.com"], cwd=test_dir)
    m_dir = test_dir / "recon" / "testaspnet.vulnweb.com"
    m_dir.mkdir(parents=True, exist_ok=True)
    m_file = m_dir / "manifest.json"
    m_file.write_text(json.dumps({"target": "testaspnet.vulnweb.com", "endpoints": ["http://testaspnet.vulnweb.com/login.aspx"]}), encoding="utf-8")
    rc_k, out_k, _ = run_cli(["knowledge", "search", "aspnet"], cwd=test_dir)
    rc_ac, out_ac, _ = run_cli(["analyze", "context"], cwd=test_dir)
    rc_as, out_as, _ = run_cli(["surface", "testaspnet.vulnweb.com", "--manifest", str(m_file)], cwd=test_dir)
    rc_sk, out_sk, _ = run_cli(["skills", "recommend", "http://testaspnet.vulnweb.com/login.aspx", "--technology", "ASP.NET"], cwd=test_dir)

    results["9_cli_commands_work"] = (
        rc_k == 0 and "ASP.NET" in out_k and
        rc_ac == 0 and "Context" in out_ac and
        rc_as == 0 and
        rc_sk == 0 and "hunt-aspnet" in out_sk
    )

    print("\n==================================================")
    passed_cnt = 0
    for k, v in results.items():
        status = "PASS" if v else "FAIL"
        if v:
            passed_cnt += 1
        print(f"[{k}] {status}")
    print("==================================================")
    print(f" TOTAL VERIFICATIONS PASSED: {passed_cnt} / {len(results)}")
    print(f" OVERALL PHASE 7.0 SUITE RESULT: {'PASS' if passed_cnt == len(results) else 'FAIL'}")
    print("==================================================")

    if test_dir.exists():
        shutil.rmtree(test_dir)

    return 0 if passed_cnt == len(results) else 1

if __name__ == "__main__":
    sys.exit(run_phase70_tests())
