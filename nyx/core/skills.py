"""
NYX Security Skill Registry & Metadata Parser
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from nyx.infrastructure.filesystem import REPO_ROOT


def get_skills_dirs() -> list[Path]:
    dirs = []
    p1 = REPO_ROOT / ".agents" / "skills"
    p2 = REPO_ROOT / "skills"
    if p1.exists():
        dirs.append(p1)
    if p2.exists():
        dirs.append(p2)
    return dirs


def parse_skill_metadata(skill_path: Path | str) -> dict:
    p = Path(skill_path)
    if p.is_dir():
        p = p / "SKILL.md"

    if not p.exists():
        return {}

    text = p.read_text(encoding="utf-8")
    name = p.parent.name

    desc = ""
    m_desc = re.search(r"^description:\s*(.+?)(?=\n[a-z_]+:|^---|\Z)", text, re.M | re.S)
    if m_desc:
        desc = m_desc.group(1).strip().strip('"').strip("'")

    category = "vulnerability"
    if name.startswith("hunt-"):
        category = name.replace("hunt-", "")
    elif "recon" in name:
        category = "recon"
    elif "report" in name or "triage" in name:
        category = "reporting"
    elif "pipeline" in name or "attack" in name:
        category = "redteam"

    techs = ["web", "api"]
    if "aspnet" in name:
        techs = ["ASP.NET", "Windows"]
    elif "laravel" in name:
        techs = ["PHP", "Laravel"]
    elif "springboot" in name:
        techs = ["Java", "Spring Boot"]
    elif "react" in name or "nextjs" in name:
        techs = ["JavaScript", "React"]
    elif "aws" in name or "cloud" in name:
        techs = ["AWS", "Cloud"]

    # Extract required tools dynamically from SKILL.md
    req_tools = []
    for tool_kw in ["subfinder", "httpx", "katana", "nuclei", "curl", "python", "nmap", "ffuf", "hydra", "sqlmap", "ysoserial"]:
        if tool_kw in text.lower():
            req_tools.append(tool_kw)

    exec_cls = "unknown"
    if "active" in text.lower() or "exploit" in text.lower():
        exec_cls = "ACTIVE"
    elif "recon" in text.lower() or "passive" in text.lower():
        exec_cls = "PASSIVE"
    elif req_tools:
        exec_cls = "SAFE_ACTIVE"

    return {
        "name": name,
        "description": desc[:300],
        "category": category,
        "technology": techs,
        "required_tools": req_tools or ["unknown"],
        "execution_class": exec_cls,
        "evidence_requirements": ["http_request", "http_response"],
        "validation_requirements": [
            "authorization test",
            "impact confirmation",
            "empirical request/response evidence"
        ],
        "path": str(p.parent)
    }


def load_skills() -> dict[str, dict]:
    skills_map = {}
    for s_dir in get_skills_dirs():
        for s_folder in s_dir.iterdir():
            if not s_folder.is_dir():
                continue
            meta = parse_skill_metadata(s_folder)
            if meta:
                skills_map[meta["name"]] = meta
    return skills_map


def list_skills(category: str | None = None) -> list[dict]:
    all_s = load_skills()
    if not category:
        return list(all_s.values())
    cat_lower = category.lower()
    return [s for s in all_s.values() if s.get("category", "").lower() == cat_lower]


def search_skills(query: str) -> list[dict]:
    all_s = load_skills()
    q = query.lower()
    matches = []
    for name, s_info in all_s.items():
        if q in name.lower() or q in s_info["description"].lower() or q in s_info["category"].lower():
            matches.append(s_info)
    return matches


def get_skill(name: str) -> dict | None:
    all_s = load_skills()
    return all_s.get(name)


def recommend_skills(url: str, technology: str | None = None) -> list[dict]:
    from nyx.core.router import recommend_skills as router_recommend
    rec = router_recommend(url, technology=technology)
    matched_skills = []
    all_s = load_skills()
    for s_name in rec.get("recommended_skills", []):
        sk = all_s.get(s_name)
        if sk:
            matched_skills.append(sk)
    return matched_skills
