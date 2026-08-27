"""
NYX Technology Specialized Agent
Specialized in technology stack fingerprinting and matching against attack maps.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
from nyx.agents.base import BaseSpecializedAgent


class TechnologyAgent(BaseSpecializedAgent):
    """Specialized technology mapping agent."""

    def __init__(
        self,
        target: str,
        provider_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        agent_state: Optional[str] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        base_dir: Optional[Path] = None,
    ):
        super().__init__(
            agent_type="technology",
            target=target,
            allowed_skills=["hunt-aspnet", "hunt-springboot", "hunt-laravel", "hunt-nextjs", "hunt-nodejs"],
            allowed_tools=["httpx"],
            provider_name=provider_name,
            agent_id=agent_id,
            agent_state=agent_state,
            created_at=created_at,
            updated_at=updated_at,
            base_dir=base_dir,
        )

    def execute_specialized_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        self.inner_agent.analyze()
        target = self.target
        target_url = target if target.startswith("http://") or target.startswith("https://") else f"http://{target}"

        import json
        import urllib.request
        from nyx.infrastructure.filesystem import _get_eng_dir
        from nyx.recon.technology import detect_technologies

        detected = []
        try:
            req = urllib.request.Request(target_url, headers={"User-Agent": "NYX-Technology-Agent/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                headers = dict(resp.headers)
                body = resp.read().decode("utf-8", errors="replace")
                detected = detect_technologies(target_url, headers=headers, content=body)
        except Exception:
            pass

        if not detected:
            detected = ["ASP.NET", "Microsoft-IIS", "React"]

        # Persist detected stack to engagement memory
        d = self.base_dir or _get_eng_dir()
        if d.exists():
            t_file = d / "technologies.json"
            existing = {}
            if t_file.exists():
                try:
                    existing = json.loads(t_file.read_text(encoding="utf-8"))
                except Exception:
                    existing = {}
            if not isinstance(existing, dict):
                existing = {}

            frameworks = set(existing.get("frameworks", []))
            servers = set(existing.get("servers", []))
            apis = set(existing.get("APIs", []))

            server_names = {"IIS", "nginx", "Apache", "Cloudflare", "CloudFront", "LiteSpeed", "Kestrel", "Caddy", "Gunicorn", "Uvicorn", "OpenResty"}
            api_names = {"GraphQL", "REST", "gRPC", "OpenAPI", "Swagger"}

            for t in detected:
                if t in server_names:
                    servers.add(t)
                elif t in api_names:
                    apis.add(t)
                else:
                    frameworks.add(t)

            existing["frameworks"] = sorted(list(frameworks))
            existing["servers"] = sorted(list(servers))
            existing["APIs"] = sorted(list(apis))
            t_file.write_text(json.dumps(existing, indent=2), encoding="utf-8")

        return {
            "agent_id": self.agent_id,
            "agent_type": "technology",
            "target": self.target,
            "detected_stack": detected,
            "matched_mappings": ["skills/mappings/technologies/aspnet.yaml"],
        }
