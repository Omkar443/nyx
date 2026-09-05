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


_SKILLS_CACHE: dict[str, dict] | None = None


def load_skills() -> dict[str, dict]:
    global _SKILLS_CACHE
    if _SKILLS_CACHE is not None:
        return _SKILLS_CACHE
    skills_map = {}
    for s_dir in get_skills_dirs():
        for s_folder in s_dir.iterdir():
            if not s_folder.is_dir():
                continue
            meta = parse_skill_metadata(s_folder)
            if meta:
                skills_map[meta["name"]] = meta
    _SKILLS_CACHE = skills_map
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


def resolve_skill_path(skill_ref: str) -> Path | None:
    """Resolve a skill name or reference label to its SKILL.md Path on disk."""
    if not skill_ref:
        return None
    ref_norm = skill_ref.strip().lower().replace("_", "-").replace(" ", "-")

    # Common alias mappings
    alias_map = {
        "7-question-gate": "triage-validation",
        "evidence-hygiene": "evidence-hygiene",
        "auth-bypass-matrix": "hunt-auth-bypass",
        "graphql-node-id-idor": "hunt-graphql",
        "graphql-fintech-mutations": "hunt-fintech-graphql",
        "tech-matrix": "bb-methodology",
        "skill-routing-engine": "bb-methodology",
        "tech-fingerprint-001": "web2-recon",
        "crawl-harvest-001": "hunt-source-leak",
    }
    target_name = alias_map.get(ref_norm, ref_norm)

    for s_dir in get_skills_dirs():
        # Direct folder match
        cand1 = s_dir / target_name / "SKILL.md"
        if cand1.exists():
            return cand1
        # With hunt- prefix
        if not target_name.startswith("hunt-"):
            cand2 = s_dir / f"hunt-{target_name}" / "SKILL.md"
            if cand2.exists():
                return cand2
        # Fuzzy match directory name
        for sub in s_dir.iterdir():
            if sub.is_dir() and (sub.name.lower() == target_name or target_name in sub.name.lower()):
                cand3 = sub / "SKILL.md"
                if cand3.exists():
                    return cand3

    return None


def get_skill_summary(skill_ref: str, max_chars: int = 250) -> str | None:
    """Extract a concise 2-3 line summary from skill frontmatter or opening paragraph."""
    p = resolve_skill_path(skill_ref)
    if not p or not p.exists():
        return None
    try:
        text = p.read_text(encoding="utf-8")
        # 1. Try frontmatter description
        m_desc = re.search(r"^description:\s*(.+?)(?=\n[a-z_]+:|^---|\Z)", text, re.M | re.S)
        if m_desc:
            desc = m_desc.group(1).strip().strip('"').strip("'")
            desc = re.sub(r"\s+", " ", desc)
            if len(desc) > max_chars:
                return desc[:max_chars].rstrip() + "..."
            return desc

        # 2. Fallback to opening content after frontmatter
        body = re.sub(r"^---.*?---\s*", "", text, flags=re.DOTALL).strip()
        lines = [l.strip() for l in body.splitlines() if l.strip() and not l.startswith("#")]
        if lines:
            first_para = " ".join(lines[:3])
            first_para = re.sub(r"\s+", " ", first_para)
            if len(first_para) > max_chars:
                return first_para[:max_chars].rstrip() + "..."
            return first_para
    except Exception:
        pass
    return None


def get_candidates_skill_summaries(candidates: list[dict], max_tokens: int = 500) -> str:
    """Tier 1: Generate compact reference playbook summaries for all candidate skills under token budget."""
    if not candidates:
        return ""

    seen_skills = set()
    summary_lines = []
    max_chars = max_tokens * 4  # rough token approximation

    for cand in candidates:
        refs = cand.get("knowledge_refs") or []
        for ref in refs:
            resolved_p = resolve_skill_path(ref)
            if not resolved_p:
                continue
            skill_name = resolved_p.parent.name
            if skill_name in seen_skills:
                continue
            seen_skills.add(skill_name)
            summary = get_skill_summary(ref, max_chars=200)
            if summary:
                summary_lines.append(f"• {skill_name}: {summary}")

    result = "\n".join(summary_lines)
    if len(result) > max_chars:
        result = result[:max_chars].rstrip() + "\n[... truncated to fit token budget ...]"
    return result


def get_skill_content(skill_ref: str, max_tokens: int = 1500) -> str | None:
    """Tier 2: Load full SKILL.md body for selected candidate, prioritizing verification gates over bypass tables."""
    p = resolve_skill_path(skill_ref)
    if not p or not p.exists():
        return None
    try:
        text = p.read_text(encoding="utf-8")
        # Strip frontmatter
        body = re.sub(r"^---.*?---\s*", "", text, flags=re.DOTALL).strip()
        max_chars = max_tokens * 4

        if len(body) <= max_chars:
            return body

        # Priority-aware truncation: extract sections and prioritize verification gates
        sections = re.split(r"(?=\n##\s+)", "\n" + body)
        priority_sections = []
        secondary_sections = []

        gate_keywords = ["gate", "confirm", "validation", "triage", "crown jewel", "false positive", "evidence", "signals", "what is confirmation"]
        bypass_keywords = ["bypass table", "bypass technique", "wordlist", "payload list", "cheatsheet", "encoding table"]

        for sec in sections:
            sec_clean = sec.strip()
            if not sec_clean:
                continue
            first_line = sec_clean.splitlines()[0].lower()
            if any(k in first_line for k in gate_keywords):
                priority_sections.append(sec_clean)
            elif any(k in first_line for k in bypass_keywords):
                secondary_sections.append(sec_clean)
            else:
                priority_sections.append(sec_clean)

        assembled = []
        current_len = 0

        # First add high priority sections
        for sec in priority_sections:
            if current_len + len(sec) + 2 <= max_chars:
                assembled.append(sec)
                current_len += len(sec) + 2
            else:
                remaining = max_chars - current_len - 60
                if remaining > 100:
                    truncated_part = sec[:remaining].rstrip() + "\n[... Section truncated for context budget ...]"
                    assembled.append(truncated_part)
                    current_len += len(truncated_part) + 2
                break

        # If room remains, add secondary sections
        if current_len < max_chars - 100:
            for sec in secondary_sections:
                if current_len + len(sec) + 2 <= max_chars:
                    assembled.append(sec)
                    current_len += len(sec) + 2
                else:
                    remaining = max_chars - current_len - 60
                    if remaining > 100:
                        truncated_part = sec[:remaining].rstrip() + "\n[... Section truncated for context budget ...]"
                        assembled.append(truncated_part)
                        current_len += len(truncated_part) + 2
                    break

        final_res = "\n\n".join(assembled)
        if len(final_res) > max_chars:
            final_res = final_res[:max_chars].rstrip()
        return final_res
    except Exception:
        return None

