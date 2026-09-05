"""
NYX Core Knowledge Loader & Search Engine
"""
from __future__ import annotations
import json
import os
import yaml
from pathlib import Path
from nyx.infrastructure.filesystem import REPO_ROOT


_KNOWLEDGE_CACHE: dict | None = None


def get_default_knowledge_dir() -> Path:
    return REPO_ROOT / "knowledge"


def load_knowledge(knowledge_dir: Path | str | None = None) -> dict:
    global _KNOWLEDGE_CACHE
    if _KNOWLEDGE_CACHE is not None and knowledge_dir is None:
        return _KNOWLEDGE_CACHE

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
                    content["_stem"] = p.stem.lower()
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

    if knowledge_dir is None:
        _KNOWLEDGE_CACHE = data
    return data


_TECH_CACHE: dict[tuple[str, str], dict | None] = {}


def load_technology(tech_name: str, knowledge_dir: Path | str | None = None) -> dict | None:
    k_dir = Path(knowledge_dir) if knowledge_dir else get_default_knowledge_dir()
    cache_key = (tech_name.lower().strip(), str(k_dir))
    if cache_key in _TECH_CACHE:
        return _TECH_CACHE[cache_key]

    tech_clean = tech_name.lower().replace(" ", "").replace(".", "")
    tech_dir = k_dir / "technologies"

    res = None
    if tech_dir.exists():
        for p in tech_dir.glob("*.yaml"):
            if p.stem.lower().replace(" ", "").replace(".", "") == tech_clean:
                try:
                    res = yaml.safe_load(p.read_text(encoding="utf-8"))
                    break
                except Exception:
                    res = None
                    break
    _TECH_CACHE[cache_key] = res
    return res


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


def search_knowledge(
    technology: str | list[str] | None = None,
    keyword: str | list[str] | None = None,
    attack_surface: str | None = None,
    vulnerability_class: str | None = None,
    category: str | None = None,
    phase: str | None = None,
    knowledge_dir: Path | str | None = None,
) -> dict:
    all_k = load_knowledge(knowledge_dir=knowledge_dir)
    results = {
        "matched_technologies": [],
        "matched_vulnerabilities": [],
        "matched_skills": [],
        "primary_intent": "general",
    }

    # Normalize inputs
    keywords: list[str] = []
    if isinstance(keyword, list):
        keywords = [k.lower().strip() for k in keyword if k]
    elif keyword:
        keywords = [keyword.lower().strip()]

    if vulnerability_class:
        keywords.append(vulnerability_class.lower().strip())
    if category:
        keywords.append(category.lower().strip())

    technologies: list[str] = []
    if isinstance(technology, list):
        technologies = [t.lower().strip() for t in technology if t]
    elif technology:
        technologies = [technology.lower().strip()]

    surface = (attack_surface or "").lower().strip()

    tech_matches_direct = []
    tech_matches_indirect = []

    for t_key, t_val in all_k.get("technologies", {}).items():
        t_obj = t_val.get("technology", {})
        t_name = t_obj.get("name", t_key).lower()
        t_category = t_obj.get("category", "").lower()
        t_desc = t_obj.get("description", "").lower()
        t_yaml_str = json.dumps(t_val).lower()

        is_direct = False
        is_indirect = False

        for kw in keywords:
            if kw == t_name or kw == t_category or (f" {kw} " in f" {t_name} "):
                is_direct = True
            elif kw in t_name or kw in t_desc:
                is_direct = True
            elif kw in t_yaml_str:
                is_indirect = True

        for tech in technologies:
            norm_tech = tech.replace(".", "").replace(" ", "").replace("-", "")
            norm_tname = t_name.replace(".", "").replace(" ", "").replace("-", "")
            stem = t_val.get("_stem", "")
            if norm_tech in norm_tname or norm_tname in norm_tech or norm_tech == stem:
                is_direct = True

        if surface and (surface in t_yaml_str or surface in t_category):
            is_indirect = True

        if is_direct:
            tech_matches_direct.append(t_val)
        elif is_indirect:
            tech_matches_indirect.append(t_val)

        if is_direct or is_indirect:
            for sk in t_val.get("related_skills", []):
                if sk not in results["matched_skills"]:
                    results["matched_skills"].append(sk)

    vuln_matches_direct = []
    vuln_matches_indirect = []

    for v_key, v_val in all_k.get("vulnerabilities", {}).items():
        v_obj = v_val.get("vulnerability", {})
        v_name = v_obj.get("name", v_key).lower()
        v_category = v_obj.get("category", "").lower()
        v_desc = v_obj.get("description", "").lower()
        v_surf = str(v_val.get("attack_surface", "")).lower()
        v_yaml_str = json.dumps(v_val).lower()

        is_direct = False
        is_indirect = False

        for kw in keywords:
            if kw == v_name or kw == v_category or kw == v_key or (f" {kw} " in f" {v_name} "):
                is_direct = True
            elif kw in v_name or kw in v_category or kw in v_desc:
                is_direct = True
            elif kw in v_yaml_str:
                is_indirect = True

        for tech in technologies:
            if tech and tech in v_yaml_str:
                is_indirect = True

        if surface and (surface in v_surf or surface in v_category or surface in v_yaml_str):
            is_direct = True

        if is_direct:
            vuln_matches_direct.append(v_val)
        elif is_indirect:
            vuln_matches_indirect.append(v_val)

        if is_direct or is_indirect:
            for sk in v_val.get("related_skills", []):
                if sk not in results["matched_skills"]:
                    results["matched_skills"].append(sk)

    # Primary intent classification
    first_kw = keywords[0] if keywords else ""
    exact_tech_name = any(
        first_kw == t.get("technology", {}).get("name", "").lower() or first_kw == t.get("_stem", "")
        for t in tech_matches_direct
    )
    exact_vuln_name = any(
        first_kw == v.get("vulnerability", {}).get("name", "").lower() for v in vuln_matches_direct
    )

    if vuln_matches_direct and not tech_matches_direct:
        results["primary_intent"] = "vulnerability"
    elif tech_matches_direct and not vuln_matches_direct:
        results["primary_intent"] = "technology"
    elif exact_tech_name and not exact_vuln_name:
        results["primary_intent"] = "technology"
    elif exact_vuln_name and not exact_tech_name:
        results["primary_intent"] = "vulnerability"
    else:
        results["primary_intent"] = "vulnerability" if len(vuln_matches_direct) >= len(tech_matches_direct) else "technology"

    results["matched_vulnerabilities"] = vuln_matches_direct + vuln_matches_indirect
    results["matched_technologies"] = tech_matches_direct + tech_matches_indirect

    return results


def retrieve_context_knowledge(
    context: dict,
    knowledge_dir: Path | str | None = None,
    limit: int = 10,
) -> dict:
    """Extract relevant security knowledge records based on mission target context."""
    technologies = [str(t).lower() for t in context.get("technologies", []) if t]
    endpoints = [str(e).lower() for e in context.get("endpoints", []) if e]
    phase = str(context.get("phase", "DISCOVERY")).upper()
    findings = context.get("findings", [])

    keywords: list[str] = []
    surfaces: list[str] = []

    # Detect endpoint patterns and map to attack surfaces / keywords
    ep_str = " ".join(endpoints)
    if "graphql" in ep_str:
        surfaces.append("api")
        keywords.append("graphql")
        if any(k in ep_str for k in ["payment", "transfer", "wallet", "checkout", "billing", "withdraw"]):
            keywords.append("fintech")
    if any(k in ep_str for k in ["login", "auth", "oauth", "sso", "saml", "signin", "reset-password"]):
        surfaces.append("authentication")
        keywords.append("authentication")
    if any(k in ep_str for k in ["upload", "avatar", "file", "attachment"]):
        surfaces.append("file_upload")
        keywords.append("file upload")
    if any(k in ep_str for k in ["actuator", "env", "heapdump"]):
        keywords.append("spring")
    if any(k in ep_str for k in ["_next", "server-action", "rsc"]):
        keywords.append("nextjs")

    # Add findings context
    for f in findings:
        if isinstance(f, dict):
            v_title = str(f.get("vulnerability") or f.get("title") or "").lower()
            if v_title:
                keywords.append(v_title)

    # Perform multi-faceted search
    search_res = search_knowledge(
        technology=technologies if technologies else None,
        keyword=keywords if keywords else None,
        attack_surface=surfaces[0] if surfaces else None,
        phase=phase,
        knowledge_dir=knowledge_dir,
    )

    matched_techs = search_res.get("matched_technologies", [])[:limit]
    matched_vulns = search_res.get("matched_vulnerabilities", [])[:limit]
    matched_skills = search_res.get("matched_skills", [])[:limit]

    # Extract relevant CVEs
    cves = []
    for v in matched_vulns:
        if isinstance(v, dict):
            for cve in v.get("related_cves", []):
                if cve not in cves:
                    cves.append(cve)

    return {
        "matched_technologies": [t.get("technology", {}).get("name", "") for t in matched_techs if isinstance(t, dict)],
        "matched_vulnerabilities": [v.get("vulnerability", {}).get("name", "") for v in matched_vulns if isinstance(v, dict)],
        "recommended_skills": matched_skills,
        "attack_surfaces": surfaces,
        "related_cves": cves[:5],
    }
