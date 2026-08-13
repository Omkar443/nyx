#!/usr/bin/env python3
"""
Phase 8.0 — NYX Recon Intelligence Engine Automated Test Suite
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

def run_phase80_tests():
    test_dir = REPO_ROOT / "test-phase80-workspace"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    print("==================================================")
    print(" PHASE 8.0 NYX RECON INTELLIGENCE ENGINE TESTS")
    print("==================================================")

    # 1. Recon Modules Import
    try:
        import nyx.recon.discovery
        import nyx.recon.crawler
        import nyx.recon.javascript
        import nyx.recon.api
        import nyx.recon.technology
        import nyx.recon.parameters
        import nyx.recon.normalizer
        import nyx.recon.intelligence
        import nyx.models.asset
        import nyx.models.endpoint
        import nyx.models.technology
        results["1_recon_modules_import"] = True
    except Exception as e:
        print(f"Import error: {e}")
        results["1_recon_modules_import"] = False

    # 2. URL Normalization Works
    from nyx.recon.normalizer import normalize_endpoint_url, deduplicate_endpoints
    norm_url = normalize_endpoint_url("HTTP://EXAMPLE.COM:80/api/?b=2&a=1#frag")
    results["2_url_normalization_works"] = (norm_url == "http://example.com/api?a=1&b=2")

    # 3. Duplicate Endpoints Removed
    deduped = deduplicate_endpoints(["http://example.com/login", "http://example.com/login/", "HTTP://EXAMPLE.COM/login"])
    results["3_duplicate_endpoints_removed"] = (len(deduped) == 1 and deduped[0] == "http://example.com/login")

    # 4. JavaScript Extraction Works
    from nyx.recon.javascript import extract_endpoints_from_js, extract_api_routes
    js_code = 'const url = "/api/v1/users"; const q = "/graphql";'
    js_eps = extract_endpoints_from_js(js_code)
    js_routes = extract_api_routes(js_code)
    results["4_javascript_extraction_works"] = (
        "/api/v1/users" in js_routes and "/graphql" in js_routes
    )

    # 5. API Detection Works
    from nyx.recon.api import detect_apis
    api_res = detect_apis("/api/v1/users")
    results["5_api_detection_works"] = (len(api_res) > 0 and api_res[0].get("type") == "rest_api")

    # 6. GraphQL Detection Works
    gql_res = detect_apis("/graphql")
    results["6_graphql_detection_works"] = (len(gql_res) > 0 and gql_res[0].get("type") == "graphql")

    # 7. Swagger Detection Works
    swg_res = detect_apis("/swagger.json")
    results["7_swagger_detection_works"] = (len(swg_res) > 0 and swg_res[0].get("type") == "openapi_swagger")

    # 8. Parameter Classification Works
    from nyx.recon.parameters import classify_parameter
    p_id = classify_parameter("id")
    p_tok = classify_parameter("token")
    results["8_parameter_classification_works"] = (
        p_id.get("type") == "object_identifier" and p_tok.get("type") == "authentication"
    )

    # 9. Technology Detection Works
    from nyx.recon.technology import detect_technologies
    techs = detect_technologies("example.com", content="<input name='__VIEWSTATE' />")
    results["9_technology_detection_works"] = ("ASP.NET" in techs)

    # 10. Attack Surface Scoring Works
    from nyx.recon.intelligence import score_endpoint
    sc = score_endpoint("/login.aspx", technology=["ASP.NET"], parameters=["username"])
    results["10_attack_surface_scoring_works"] = (sc.get("risk_score") >= 60 and sc.get("priority") == "HIGH")

    # 11. Knowledge Integration Works
    from nyx.core.knowledge import load_technology
    asp_k = load_technology("ASP.NET")
    results["11_knowledge_integration_works"] = (asp_k is not None and "hunt-aspnet" in asp_k.get("related_skills", []))

    # 12. CLI Commands Work
    rc_intel, out_intel, _ = run_cli(["recon", "intelligence", "example.com"], cwd=test_dir)
    rc_js, out_js, _ = run_cli(["recon", "js", "http://example.com/app.js"], cwd=test_dir)
    rc_api, out_api, _ = run_cli(["recon", "api", "http://example.com/api"], cwd=test_dir)
    rc_param, out_param, _ = run_cli(["recon", "parameters"], cwd=test_dir)

    results["12_cli_commands_work"] = (
        rc_intel == 0 and "NYX Recon Intelligence" in out_intel and
        rc_js == 0 and "JavaScript Intelligence" in out_js and
        rc_api == 0 and "API Discovery" in out_api and
        rc_param == 0 and "Parameter Intelligence" in out_param
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
    print(f" OVERALL PHASE 8.0 SUITE RESULT: {'PASS' if passed_cnt == len(results) else 'FAIL'}")
    print("==================================================")

    if test_dir.exists():
        shutil.rmtree(test_dir)

    return 0 if passed_cnt == len(results) else 1

if __name__ == "__main__":
    sys.exit(run_phase80_tests())
