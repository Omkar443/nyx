"""
NYX Recon Subdomain & Live Host Discovery Module
"""
from __future__ import annotations
import json
from pathlib import Path
from nyx.infrastructure.filesystem import _get_eng_dir


def discover_subdomains(target: str) -> list[str]:
    d = _get_eng_dir()
    manifest_file = Path.cwd() / "recon" / target / "manifest.json"
    subs = set()
    subs.add(target)

    if manifest_file.exists():
        try:
            m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
            for s in m_data.get("subdomains", []):
                subs.add(s)
        except Exception:
            pass
    return sorted(list(subs))


def discover_live_hosts(target: str) -> list[str]:
    d = _get_eng_dir()
    manifest_file = Path.cwd() / "recon" / target / "manifest.json"
    hosts = set()
    hosts.add(f"https://{target}")
    hosts.add(f"http://{target}")

    if manifest_file.exists():
        try:
            m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
            for h in m_data.get("hosts", []):
                hosts.add(h.get("url") if isinstance(h, dict) else str(h))
        except Exception:
            pass
    return sorted(list(hosts))
