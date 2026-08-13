"""
Phase 21.8 Verification Suite — NYX Final Ownership, Supply Chain & Release Audit
Tests:
1. NYX core package imports cleanly (nyx)
2. NYX CLI package imports cleanly (nyx_cli.cli)
3. Script runner scripts/nyx.py exists
4. Wheel package contains zero legacy nyx/claude files
5. Release audit reports exist in docs/
6. Open source documentation files complete
7. pyproject.toml package metadata clean
8. Skills preserved (skills/ and skills/public/)
9. Knowledge maps preserved (knowledge/)
10. Pre-release checklist complete (docs/release_checklist.md)
"""
from __future__ import annotations

import glob
import os
import shutil
import sys
import zipfile

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def run_phase218_release_audit_tests():
    print("=" * 60)
    print(" PHASE 21.8 NYX FINAL OWNERSHIP, SUPPLY CHAIN & RELEASE AUDIT")
    print("=" * 60)

    results = {}

    # 1. NYX Core package import
    try:
        import nyx
        import nyx.core
        core_ok = True
    except Exception as e:
        print(f"Core Import Error: {e}")
        core_ok = False
    print(f"[1_nyx_core_import] nyx core imports cleanly: {core_ok}")
    results["1_nyx_core_import"] = core_ok

    # 2. NYX CLI package import
    try:
        import nyx_cli.cli
        cli_ok = True
    except Exception as e:
        print(f"CLI Import Error: {e}")
        cli_ok = False
    print(f"[2_nyx_cli_import] nyx_cli.cli imports cleanly: {cli_ok}")
    results["2_nyx_cli_import"] = cli_ok

    # 3. Script runner scripts/nyx.py
    script_path = REPO_ROOT / "scripts" / "nyx.py"
    script_ok = script_path.exists()
    print(f"[3_script_runner] scripts/nyx.py exists: {script_ok}")
    results["3_script_runner"] = script_ok

    # 4. Wheel Supply Chain Audit (zero legacy files)
    wheels = glob.glob(str(REPO_ROOT / "dist" / "*.whl"))
    whl_clean = False
    if wheels:
        with zipfile.ZipFile(wheels[0], 'r') as z:
            names = z.namelist()
            legacy = [n for n in names if "nyx" in n.lower() or "nyx_security_engine" in n.lower()]
            whl_clean = (len(legacy) == 0)
    print(f"[4_wheel_supply_chain] Wheel exists & clean (0 legacy files): {whl_clean}")
    results["4_wheel_supply_chain"] = whl_clean

    # 5. Release Audit Reports
    audit_docs = ["final_identity_audit.md", "git_history_audit.md", "knowledge_release_audit.md", "dependency_audit.md", "release_checklist.md"]
    audits_ok = all((REPO_ROOT / "docs" / d).exists() for d in audit_docs)
    print(f"[5_release_audits] All 5 release audit reports exist in docs/: {audits_ok}")
    results["5_release_audits"] = audits_ok

    # 6. Open Source Docs
    os_docs = ["README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md"]
    docs_ok = all((REPO_ROOT / d).exists() for d in os_docs)
    print(f"[6_opensource_docs] Release markdown files complete: {docs_ok}")
    results["6_opensource_docs"] = docs_ok

    # 7. pyproject.toml package metadata
    pyproj = REPO_ROOT / "pyproject.toml"
    metadata_ok = False
    if pyproj.exists():
        txt = pyproj.read_text(encoding="utf-8")
        metadata_ok = ('name = "nyx-security-engine"' in txt) and ('nyx = "nyx_cli.cli:main"' in txt)
    print(f"[7_pyproject_metadata] pyproject.toml metadata clean: {metadata_ok}")
    results["7_pyproject_metadata"] = metadata_ok

    # 8. Skills Preserved
    skills_dir = REPO_ROOT / "skills"
    pub_skills = REPO_ROOT / "skills" / "public"
    skills_ok = skills_dir.exists() and pub_skills.exists() and len(list(skills_dir.glob("*"))) > 0
    print(f"[8_skills_preserved] Skills preserved: {skills_ok}")
    results["8_skills_preserved"] = skills_ok

    # 9. Knowledge Maps Preserved
    knowledge_dir = REPO_ROOT / "knowledge"
    knowledge_ok = knowledge_dir.exists() and len(list(knowledge_dir.glob("*"))) > 0
    print(f"[9_knowledge_preserved] Knowledge maps preserved: {knowledge_ok}")
    results["9_knowledge_preserved"] = knowledge_ok

    # 10. Pre-release Checklist Complete
    chk_doc = REPO_ROOT / "docs" / "release_checklist.md"
    chk_ok = chk_doc.exists() and "[x]" in chk_doc.read_text(encoding="utf-8")
    print(f"[10_release_checklist] Release checklist signed off: {chk_ok}")
    results["10_release_checklist"] = chk_ok

    # Print Summary
    print("\n" + "=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    for name, res in results.items():
        status_str = "PASS" if res else "FAIL"
        print(f"[{name}] {status_str}")

    print("=" * 60)
    print(f" TOTAL VERIFICATIONS PASSED: {passed} / {total}")
    print(f" OVERALL PHASE 21.8 SUITE RESULT: {'PASS' if passed == total else 'FAIL'}")
    print("=" * 60)

    return passed == total


if __name__ == "__main__":
    success = run_phase218_release_audit_tests()
    sys.exit(0 if success else 1)
