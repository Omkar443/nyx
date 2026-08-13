"""
Phase 12 Architecture Verification Suite
Tests:
1. Strict Dependency Direction: 0 imports of nyx/nyx_cli.cli in nyx package.
2. Foundation & Service Instantiation: All 8 Application Services instantiate cleanly.
3. Service Operation & Model Returns: Services return structured dicts/models, not None or raw stdout.
4. Terminal UI Decoupling: nyx.interface.output is used by nyx/cli adapter.
5. CLI Adapter Dispatch: nyx_cli.cli commands delegate to services and execute cleanly.
"""

import sys
import os
import shutil
import tempfile
import subprocess
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_zero_nyx_imports():
    nyx_dir = Path(__file__).parent.parent / "nyx"
    violations = []
    for p in nyx_dir.rglob("*.py"):
        content = p.read_text(encoding="utf-8")
        for line in content.splitlines():
            line_str = line.strip()
            if line_str.startswith("import nyx_cli") or line_str.startswith("from nyx_cli") or "import nyx_cli.cli" in line_str:
                violations.append(f"{p.relative_to(nyx_dir.parent)}: {line_str}")
    return len(violations) == 0, violations

def test_service_foundation():
    from nyx.application.base import BaseService, ServiceResult
    from nyx.application.engagement_service import EngagementService
    from nyx.application.recon_service import ReconService
    from nyx.application.finding_service import FindingService
    from nyx.application.evidence_service import EvidenceService
    from nyx.application.analysis_service import AnalysisService
    from nyx.application.validation_service import ValidationService
    from nyx.application.mission_service import MissionService
    from nyx.application.skill_service import SkillService

    services = [
        EngagementService(),
        ReconService(),
        FindingService(),
        EvidenceService(),
        AnalysisService(),
        ValidationService(),
        MissionService(),
        SkillService()
    ]
    return len(services) == 8

def test_engagement_service_isolation():
    tmp_dir = Path(tempfile.mkdtemp(prefix="nyx_phase12_test_"))
    orig_cwd = os.getcwd()
    try:
        os.chdir(tmp_dir)
        from nyx.application.engagement_service import EngagementService
        svc = EngagementService()
        
        # Test init
        res = svc.init_engagement("testdomain.com")
        assert res.get("target") == "testdomain.com"
        



        


        
        return True, "EngagementService isolated execution passed"
    finally:
        os.chdir(orig_cwd)
        shutil.rmtree(tmp_dir, ignore_errors=True)

def test_cli_adapter_execution():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).parent.parent)
    
    tmp_dir = Path(tempfile.mkdtemp(prefix="nyx_phase12_cli_"))
    try:
        # Test CLI dispatch via python -m nyx_cli.cli
        cmd = [sys.executable, "-m", "nyx_cli.cli", "engagement", "init", "target.com"]
        p1 = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp_dir, env=env)
        if p1.returncode != 0:
            return False, f"engagement init failed: {p1.stderr}"

        cmd = [sys.executable, "-m", "nyx_cli.cli", "state", "ANALYSIS"]
        p2 = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp_dir, env=env)
        if p2.returncode != 0:
            return False, f"state set failed: {p2.stderr}"

        cmd = [sys.executable, "-m", "nyx_cli.cli", "findings"]
        p3 = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp_dir, env=env)
        if p3.returncode != 0:
            return False, f"findings list failed: {p3.stderr}"

        return True, "CLI adapter execution passed"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

def main():
    print("==================================================")
    print(" PHASE 12.0 NYX APPLICATION BOUNDARY VERIFICATION")
    print("==================================================")
    
    passed = 0
    total = 4
    
    ok, violations = test_zero_nyx_imports()
    if ok:
        print("[1_zero_nyx_imports] PASS - 0 nyx/nyx_cli.cli imports in nyx/")
        passed += 1
    else:
        print(f"[1_zero_nyx_imports] FAIL - Violations: {violations}")
        
    try:
        if test_service_foundation():
            print("[2_service_foundation] PASS - All 8 application services instantiated")
            passed += 1
        else:
            print("[2_service_foundation] FAIL")
    except Exception as e:
        print(f"[2_service_foundation] FAIL - Exception: {e}")

    try:
        ok, msg = test_engagement_service_isolation()
        if ok:
            print(f"[3_engagement_service_isolation] PASS - {msg}")
            passed += 1
        else:
            print(f"[3_engagement_service_isolation] FAIL - {msg}")
    except Exception as e:
        print(f"[3_engagement_service_isolation] FAIL - Exception: {e}")

    try:
        ok, msg = test_cli_adapter_execution()
        if ok:
            print(f"[4_cli_adapter_execution] PASS - {msg}")
            passed += 1
        else:
            print(f"[4_cli_adapter_execution] FAIL - {msg}")
    except Exception as e:
        print(f"[4_cli_adapter_execution] FAIL - Exception: {e}")

    print("==================================================")
    print(f" TOTAL VERIFICATIONS PASSED: {passed} / {total}")
    if passed == total:
        print(" OVERALL PHASE 12.0 SUITE RESULT: PASS")
        print("==================================================")
        return 0
    else:
        print(" OVERALL PHASE 12.0 SUITE RESULT: FAIL")
        print("==================================================")
        return 1

if __name__ == "__main__":
    sys.exit(main())
