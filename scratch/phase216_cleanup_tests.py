"""
Phase 21.6 Cleanup & Open Source Finalization Verification Suite
Tests:
1. No runtime nyx imports in nyx/* or nyx_cli/*
2. nyx/ directory does not exist (migrated to nyx_cli/)
3. nyx_cli/ directory exists
4. legacy nyx_security_engine.egg-info/ directory removed
5. scripts/nyx.py exists and scripts/nyx.py removed
6. NYX CLI module entry point imports cleanly
7. Public skill directory skills/public/ exists
8. All knowledge assets (skills/, knowledge/, .agents/) intact
9. Private Research Assets externalized & audited in docs/skill_release_audit.md
10. pyproject.toml package definitions updated to nyx_cli
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import sys

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def run_phase216_cleanup_tests():
    print("=" * 60)
    print(" PHASE 21.6 NYX LEGACY CLEANUP & IDENTITY MIGRATION TESTS")
    print("=" * 60)

    results = {}

    # 1. Zero nyx imports in nyx/* and nyx_cli/*
    py_files = glob.glob(str(REPO_ROOT / "nyx" / "**" / "*.py"), recursive=True) + \
               glob.glob(str(REPO_ROOT / "nyx_cli" / "**" / "*.py"), recursive=True)

    nyx_imports = []
    for fpath in py_files:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
            for line_no, line in enumerate(fp, 1):
                if "import nyx." in line or "from nyx." in line:
                    rel = Path(fpath).relative_to(REPO_ROOT)
                    nyx_imports.append(f"{rel}:{line_no}: {line.strip()}")

    print(f"[1_zero_nyx_imports] Total nyx imports in nyx/ and nyx_cli/: {len(nyx_imports)}")
    results["1_zero_nyx_imports"] = (len(nyx_imports) == 0)

    # 2. Old nyx/ directory removed
    old_nyx_dir = REPO_ROOT / "nyx"
    print(f"[2_old_nyx_dir_removed] nyx/ directory removed: {not old_nyx_dir.exists()}")
    results["2_old_nyx_dir_removed"] = (not old_nyx_dir.exists())

    # 3. New nyx_cli/ directory exists
    new_nyx_cli_dir = REPO_ROOT / "nyx_cli"
    print(f"[3_nyx_cli_dir_exists] nyx_cli/ directory exists: {new_nyx_cli_dir.exists()}")
    results["3_nyx_cli_dir_exists"] = new_nyx_cli_dir.exists()

    # 4. Legacy egg-info removed
    old_egg_info = REPO_ROOT / "nyx_security_engine.egg-info"
    print(f"[4_legacy_egg_info_removed] nyx_security_engine.egg-info removed: {not old_egg_info.exists()}")
    results["4_legacy_egg_info_removed"] = (not old_egg_info.exists())

    # 5. Script Renamed (scripts/nyx.py exists, scripts/nyx.py removed)
    nyx_script = REPO_ROOT / "scripts" / "nyx.py"
    nyx_script = REPO_ROOT / "scripts" / "nyx.py"
    scripts_ok = nyx_script.exists() and not nyx_script.exists()
    print(f"[5_script_renamed] scripts/nyx.py exists & nyx.py removed: {scripts_ok}")
    results["5_script_renamed"] = scripts_ok

    # 6. Import nyx_cli.cli cleanly
    try:
        import nyx_cli.cli
        cli_import_ok = True
    except Exception as e:
        print(f"CLI Import Error: {e}")
        cli_import_ok = False

    print(f"[6_cli_import] nyx_cli.cli imports cleanly: {cli_import_ok}")
    results["6_cli_import"] = cli_import_ok

    # 7. Public Skills Directory
    pub_skills = REPO_ROOT / "skills" / "public"
    pub_ok = pub_skills.exists() and len(list(pub_skills.glob("*"))) > 0
    print(f"[7_public_skills] skills/public/ exists and loaded: {pub_ok}")
    results["7_public_skills"] = pub_ok

    # 8. All Research Knowledge Intact (skills/, knowledge/, .agents/)
    skills_exist = (REPO_ROOT / "skills").exists()
    knowledge_exists = (REPO_ROOT / "knowledge").exists()
    agents_exist = (REPO_ROOT / ".agents").exists()
    knowledge_ok = skills_exist and knowledge_exists and agents_exist
    print(f"[8_knowledge_assets_intact] Knowledge folders intact: {knowledge_ok}")
    results["8_knowledge_assets_intact"] = knowledge_ok

    # 9. Private Research Audit Record Present
    audit_doc = REPO_ROOT / "docs" / "skill_release_audit.md"
    audit_ok = audit_doc.exists() and "Skill Classification Matrix" in audit_doc.read_text(encoding="utf-8")
    print(f"[9_private_research_audit] Research Audit Record Valid: {audit_ok}")
    results["9_private_research_audit"] = audit_ok

    # 10. pyproject.toml package entry point updated
    pyproj = REPO_ROOT / "pyproject.toml"
    pyproj_ok = False
    if pyproj.exists():
        txt = pyproj.read_text(encoding="utf-8")
        pyproj_ok = ("nyx = \"nyx_cli.cli:main\"" in txt) and ("packages = [\"nyx_cli\"" in txt)
    print(f"[10_pyproject_updated] pyproject.toml updated: {pyproj_ok}")
    results["10_pyproject_updated"] = pyproj_ok

    # Print Summary
    print("\n" + "=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    for name, res in results.items():
        status_str = "PASS" if res else "FAIL"
        print(f"[{name}] {status_str}")

    print("=" * 60)
    print(f" TOTAL VERIFICATIONS PASSED: {passed} / {total}")
    print(f" OVERALL PHASE 21.6 SUITE RESULT: {'PASS' if passed == total else 'FAIL'}")
    print("=" * 60)

    return passed == total


if __name__ == "__main__":
    success = run_phase216_cleanup_tests()
    sys.exit(0 if success else 1)
