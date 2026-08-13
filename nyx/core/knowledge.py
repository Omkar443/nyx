"""
NYX Core Knowledge Loader & Search Engine
"""
from __future__ import annotations
import json
import os
import yaml
from pathlib import Path
from nyx.infrastructure.filesystem import REPO_ROOT


def get_default_knowledge_dir() -> Path:
    return REPO_ROOT / "knowledge"


def load_knowledge(knowledge_dir: Path | str | None = None) -> dict:
    k_dir = Path(knowledge_dir) if knowledge_dir else get_default_knowledge_dir()
    data = {"technologies": {}, "vulnerabilities": {}, "patterns": {}}

    if not k_dir.exists():
        return data

    # Load technologies
    tech_dir = k_dir / "technologies"
    if tech_dir.exists():
        for p in tech_dir.glob("*.yaml"):
            try:
                content = yaml.safe_load(p.read_text(encoding="utf-8"))
                if content and "technology" in content:
                    t_name = content["technology"].get("name", p.stem)
                    data["technologies"][t_name.lower()] = content
            except Exception:
                pass

    # Load vulnerabilities
    vuln_dir = k_dir / "vulnerabilities"
    if vuln_dir.exists():
        for p in vuln_dir.glob("**/*.yaml"):
            try:
                content = yaml.safe_load(p.read_text(encoding="utf-8"))
                if content and "vulnerability" in content:
                    v_name = content["vulnerability"].get("name", p.stem)
                    data["vulnerabilities"][v_name.lower()] = content
            except Exception:
                pass

    # Load patterns
    pat_dir = k_dir / "patterns"
    if pat_dir.exists():
        for p in pat_dir.glob("*.yaml"):
            try:
                content = yaml.safe_load(p.read_text(encoding="utf-8"))
                if content:
                    data["patterns"][p.stem] = content
            except Exception:
                pass

    return data


def load_technology(tech_name: str, knowledge_dir: Path | str | None = None) -> dict | None:
    k_dir = Path(knowledge_dir) if knowledge_dir else get_default_knowledge_dir()
    tech_clean = tech_name.lower().replace(" ", "").replace(".", "")
    tech_dir = k_dir / "technologies"

    for p in tech_dir.glob("*.yaml"):
        if p.stem.lower().replace(" ", "").replace(".", "") == tech_clean:
            try:
                return yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                return None
    return None


def load_vulnerability(vuln_name: str, knowledge_dir: Path | str | None = None) -> dict | None:
    k_dir = Path(knowledge_dir) if knowledge_dir else get_default_knowledge_dir()
    v_clean = vuln_name.lower()
    vuln_dir = k_dir / "vulnerabilities"

    for p in vuln_dir.glob("**/*.yaml"):
        if p.stem.lower() == v_clean:
            try:
                return yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return None


def search_knowledge(technology: str | None = None, keyword: str | None = None, knowledge_dir: Path | str | None = None) -> dict:
    all_k = load_knowledge(knowledge_dir=knowledge_dir)
    results = {"matched_technologies": [], "matched_vulnerabilities": [], "matched_skills": []}

    kw = (keyword or "").lower().strip()
    tech = (technology or "").lower().strip()

    for t_key, t_val in all_k.get("technologies", {}).items():
        t_name = t_val.get("technology", {}).get("name", t_key).lower()
        t_desc = t_val.get("technology", {}).get("description", "").lower()
        t_yaml_str = json.dumps(t_val).lower()

        match = False
        if tech and tech in t_name:
            match = True
        if kw and (kw in t_name or kw in t_desc or kw in t_yaml_str):
            match = True

        if match:
            results["matched_technologies"].append(t_val)
            for sk in t_val.get("related_skills", []):
                if sk not in results["matched_skills"]:
                    results["matched_skills"].append(sk)

    for v_key, v_val in all_k.get("vulnerabilities", {}).items():
        v_name = v_val.get("vulnerability", {}).get("name", v_key).lower()
        v_desc = v_val.get("vulnerability", {}).get("description", "").lower()
        v_yaml_str = json.dumps(v_val).lower()

        match = False
        if kw and (kw in v_name or kw in v_desc or kw in v_yaml_str):
            match = True
        if tech and tech in v_yaml_str:
            match = True

        if match:
            results["matched_vulnerabilities"].append(v_val)
            for sk in v_val.get("related_skills", []):
                if sk not in results["matched_skills"]:
                    results["matched_skills"].append(sk)

    return results
