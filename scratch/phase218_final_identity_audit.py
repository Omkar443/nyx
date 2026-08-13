"""
Phase 21.8 Verification Suite — NYX Final Repository Identity Purification & AI Neutralization
Verifies repository identity state with dynamic string construction to prevent self-matching during grep scans.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path("d:/Pentest/Skill File/NYX").resolve()

# Dynamic construction of target strings so the audit file does not match literal greps
T_CBH = "c" + "bh"
T_CBH_NAME = "Claude-" + "BugHunter"
T_CBH_SNAKE = "claude_" + "bughunter"
T_ELEMENTAL = "elemental" + "souls"
T_OLD_URL = "github.com/" + T_ELEMENTAL

TERMS = {
    T_CBH: re.compile(r"\b" + T_CBH + r"\b", re.IGNORECASE),
    T_CBH_NAME: re.compile(T_CBH_NAME, re.IGNORECASE),
    T_CBH_SNAKE: re.compile(T_CBH_SNAKE, re.IGNORECASE),
    T_ELEMENTAL: re.compile(T_ELEMENTAL, re.IGNORECASE),
    "old_github_url": re.compile(re.escape(T_OLD_URL), re.IGNORECASE),
}

EXCLUDED_DIR_PREFIXES = [
    "frontend/node_modules/",
    ".git/",
    "dist/",
    "build/",
    "nyx_private_backup/",
]

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg.png",
    ".woff", ".woff2", ".ttf", ".eot",
    ".whl", ".tar.gz", ".zip", ".gz", ".pdf"
}

def is_excluded(p: Path, rel_str: str) -> bool:
    for ex in EXCLUDED_DIR_PREFIXES:
        if rel_str.startswith(ex):
            return True
    if p.suffix.lower() in BINARY_EXTENSIONS:
        return True
    return False

def scan_repo() -> dict[str, list[str]]:
    matches: dict[str, list[str]] = {t: [] for t in TERMS}
    
    for p in REPO_ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel_str = str(p.relative_to(REPO_ROOT)).replace("\\", "/")
        if is_excluded(p, rel_str):
            continue
        if p.name == "phase218_final_identity_audit.py":
            continue

        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for term_name, pat in TERMS.items():
            if pat.search(txt):
                matches[term_name].append(rel_str)
                
    return matches

def main():
    print("=" * 60)
    print(" PHASE 21.8 FINAL REPOSITORY IDENTITY & AI NEUTRALIZATION AUDIT")
    print("=" * 60)

    matches = scan_repo()
    
    results = {}
    
    # 1-5: Check zero matches for legacy terms
    for term_name, file_list in matches.items():
        pass_flag = (len(file_list) == 0)
        results[f"zero_{term_name}"] = pass_flag
        status_str = "PASS" if pass_flag else f"FAIL ({len(file_list)} matches)"
        print(f"[{term_name}] Zero Matches: {status_str}")
        if file_list:
            for f in file_list[:5]:
                print(f"    - {f}")
            if len(file_list) > 5:
                print(f"    ... and {len(file_list) - 5} more")

    # 6: nyx_cli import check
    try:
        sys.path.insert(0, str(REPO_ROOT))
        import nyx_cli.cli
        results["nyx_cli_import"] = True
        print("[nyx_cli_import] Clean Import: PASS")
    except Exception as e:
        results["nyx_cli_import"] = False
        print(f"[nyx_cli_import] Clean Import: FAIL ({e})")

    # 7: pyproject metadata check
    pyproject_file = REPO_ROOT / "pyproject.toml"
    if pyproject_file.exists():
        py_txt = pyproject_file.read_text(encoding="utf-8").lower()
        valid_py = ("omkar443/nyx" in py_txt) and ("nyx-security-engine" in py_txt)
        results["pyproject_metadata"] = valid_py
        print(f"[pyproject_metadata] Correct Metadata: {'PASS' if valid_py else 'FAIL'}")
    else:
        results["pyproject_metadata"] = False
        print("[pyproject_metadata] Correct Metadata: FAIL (File Missing)")

    # 8: README branding check
    readme_file = REPO_ROOT / "README.md"
    if readme_file.exists():
        r_txt = readme_file.read_text(encoding="utf-8")
        valid_r = ("NYX Security Intelligence Engine" in r_txt)
        results["readme_branding"] = valid_r
        print(f"[readme_branding] Native NYX Branding: {'PASS' if valid_r else 'FAIL'}")
    else:
        results["readme_branding"] = False
        print("[readme_branding] Native NYX Branding: FAIL (File Missing)")

    # 9: Skills preserved check
    skills_dir = REPO_ROOT / "skills"
    agents_skills_dir = REPO_ROOT / ".agents" / "skills"
    valid_skills = skills_dir.exists() and agents_skills_dir.exists()
    results["skills_preserved"] = valid_skills
    print(f"[skills_preserved] Skills Directories Present: {'PASS' if valid_skills else 'FAIL'}")

    # 10: Knowledge assets preserved check
    knowledge_dir = REPO_ROOT / "knowledge"
    valid_knowledge = knowledge_dir.exists() and any(knowledge_dir.rglob("*"))
    results["knowledge_preserved"] = valid_knowledge
    print(f"[knowledge_preserved] Knowledge Maps Present: {'PASS' if valid_knowledge else 'FAIL'}")

    print("=" * 60)
    passed_count = sum(1 for v in results.values() if v)
    total_count = len(results)
    print(f" TOTAL VERIFICATIONS PASSED: {passed_count} / {total_count}")
    print(f" OVERALL PHASE 21.8 AUDIT RESULT: {'PASS' if passed_count == total_count else 'FAIL'}")
    print("=" * 60)

    if passed_count != total_count:
        sys.exit(1)

if __name__ == "__main__":
    main()
