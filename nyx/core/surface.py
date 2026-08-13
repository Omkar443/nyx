"""
NYX Core Attack Surface Model Graph Builder
"""
from __future__ import annotations
import json
from pathlib import Path
from nyx.infrastructure.filesystem import _get_eng_dir
from nyx.core.router import recommend_skills


def build_attack_surface_graph(target: str, endpoints: list[dict | str] | None = None, technologies: list[str] | None = None, findings: list[dict] | None = None) -> dict:
    """Build a graph model of the target's attack surface nodes:
    Target -> Technology -> Endpoint -> Parameters -> Vulnerability Hypotheses."""
    nodes = []
    edges = []

    # Target root node
    nodes.append({"type": "target", "value": target})

    # Technologies
    tech_list = list(technologies) if technologies else []
    d = _get_eng_dir()
    if not tech_list and d.exists():
        t_file = d / "technologies.json"
        if t_file.exists():
            try:
                t_data = json.loads(t_file.read_text(encoding="utf-8"))
                for cat, items in t_data.items():
                    if isinstance(items, list):
                        tech_list.extend(items)
            except Exception:
                pass

    for t in set(tech_list):
        nodes.append({"type": "technology", "value": t})
        edges.append({"source": target, "target": t, "relation": "uses_technology"})

    # Endpoints
    ep_list = list(endpoints) if endpoints else []
    if not ep_list and d.exists():
        e_file = d / "endpoints.json"
        if e_file.exists():
            try:
                ep_list = json.loads(e_file.read_text(encoding="utf-8"))
            except Exception:
                pass

    for item in ep_list:
        ep_val = item.get("url") if isinstance(item, dict) else str(item)
        if not ep_val:
            continue
        nodes.append({"type": "endpoint", "value": ep_val})
        edges.append({"source": target, "target": ep_val, "relation": "exposes_endpoint"})

        # Derive vulnerabilities using router
        rec = recommend_skills(ep_val, technology=tech_list[0] if tech_list else None)
        for surf in rec.get("attack_surface", []):
            v_val = f"{surf} vulnerability"
            if not any(n["type"] == "vulnerability" and n["value"] == v_val for n in nodes):
                nodes.append({"type": "vulnerability", "value": v_val})
            edges.append({"source": ep_val, "target": v_val, "relation": "potential_vulnerability"})

    # Findings
    f_list = list(findings) if findings else []
    if not f_list and d.exists():
        f_file = d / "findings.json"
        if f_file.exists():
            try:
                f_list = json.loads(f_file.read_text(encoding="utf-8"))
            except Exception:
                pass

    for f in f_list:
        fid = f.get("finding_id", "FH-UNKNOWN")
        ftitle = f.get("title", "Confirmed Finding")
        nodes.append({"type": "confirmed_finding", "value": f"{fid}: {ftitle}"})
        edges.append({"source": target, "target": f"{fid}: {ftitle}", "relation": "has_confirmed_finding"})

    return {
        "target": target,
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "technologies_count": len([n for n in nodes if n["type"] == "technology"]),
            "endpoints_count": len([n for n in nodes if n["type"] == "endpoint"]),
            "vulnerabilities_count": len([n for n in nodes if n["type"] == "vulnerability"]),
            "findings_count": len([n for n in nodes if n["type"] == "confirmed_finding"])
        }
    }
