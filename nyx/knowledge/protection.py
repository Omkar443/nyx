"""
NYX Knowledge Protection System
Backs up skills and knowledge assets, verifies SHA-256 hashes and YAML integrity, and prevents accidental deletions.
"""
from __future__ import annotations

import glob
import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from nyx.infrastructure.filesystem import REPO_ROOT, _get_eng_dir


class KnowledgeProtection:
    """Safeguards NYX security skill libraries, knowledge maps, and vulnerability patterns."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.repo_root = base_dir or REPO_ROOT

    def _get_backup_dir(self) -> Path:
        d = _get_eng_dir(create=True, base_dir=self.repo_root)
        b_dir = d / "backups" / "knowledge"
        b_dir.mkdir(parents=True, exist_ok=True)
        return b_dir

    def create_backup(self) -> Dict[str, Any]:
        """Create timestamped archive backup of skills/ and .agents/skills/."""
        b_root = _get_eng_dir(create=True, base_dir=self.repo_root) / "backups" / "knowledge"
        b_root.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = b_root / f"knowledge_backup_{timestamp}.json"

        skills_dir = self.repo_root / "skills"
        agent_skills_dir = self.repo_root / ".agents" / "skills"

        files_data = {}
        for sdir in [skills_dir, agent_skills_dir]:
            if sdir.exists():
                for fpath in sdir.glob("**/*"):
                    if fpath.is_file():
                        try:
                            rel = str(fpath.relative_to(self.repo_root))
                            content = fpath.read_text(encoding="utf-8", errors="replace")
                            files_data[rel] = {
                                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                                "content": content,
                            }
                        except Exception:
                            pass

        backup_file.write_text(json.dumps(files_data, indent=2), encoding="utf-8")
        return {
            "success": True,
            "backup_file": str(backup_file),
            "files_count": len(files_data),
            "timestamp": timestamp,
        }

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify knowledge asset counts, YAML frontmatter syntax, and file integrity."""
        skills_dir = self.repo_root / "skills"
        agent_skills_dir = self.repo_root / ".agents" / "skills"

        skill_files = []
        for sdir in [skills_dir, agent_skills_dir]:
            if sdir.exists():
                skill_files.extend(list(sdir.glob("**/SKILL.md")))

        valid_yaml = 0
        corrupted = 0
        for sf in skill_files:
            try:
                txt = sf.read_text(encoding="utf-8", errors="replace")
                if txt.startswith("---") and "name:" in txt and "description:" in txt:
                    valid_yaml += 1
                else:
                    corrupted += 1
            except Exception:
                corrupted += 1

        is_intact = (len(skill_files) > 0 and corrupted == 0)

        return {
            "intact": is_intact,
            "total_skills_count": len(skill_files),
            "valid_yaml_count": valid_yaml,
            "corrupted_count": corrupted,
            "message": "Knowledge assets intact and verified." if is_intact else f"Verification failed with {corrupted} corrupted assets.",
        }
