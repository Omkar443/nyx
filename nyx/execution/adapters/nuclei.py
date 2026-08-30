"""
NYX Nuclei Tool Adapter
Specialized execution & output parsing adapter for Nuclei vulnerability scanning.
"""
from __future__ import annotations

import json
from typing import Any
from nyx.execution.adapters.base import ToolAdapter
from nyx.infrastructure.tools import get_tool_executable_vector


class NucleiAdapter(ToolAdapter):
    tool_name = "nuclei"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty target URL or host."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        tool_vec = get_tool_executable_vector("nuclei") or ["nuclei"]
        cmd = list(tool_vec) + ["-u", target]
        if arguments:
            # Normalize legacy -json flag to -jsonl for Nuclei v3+ compatibility
            sanitized_args = ["-jsonl" if arg == "-json" else arg for arg in arguments]
            cmd.extend(sanitized_args)
        else:
            cmd.extend(["-jsonl"])
        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        findings = []
        for line in stdout.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("{"):
                try:
                    data = json.loads(line_str)
                    findings.append({
                        "template_id": data.get("template-id") or data.get("templateID"),
                        "name": data.get("info", {}).get("name") or data.get("name"),
                        "severity": data.get("info", {}).get("severity") or data.get("severity", "info"),
                        "matched_at": data.get("matched-at") or data.get("matched"),
                        "curl_command": data.get("curl-command"),
                    })
                except Exception:
                    pass

        return {
            "vulnerabilities": findings,
            "assets_found": len(findings),
            "count": len(findings),
            "parsed": True,
        }


NUCLEI_TEMPLATE_MAP: dict[str, dict[str, str]] = {
    "prototype_pollution": {
        "template_id": "http/vulnerabilities/other/client-side-prototype-pollution.yaml",
        "tags": "prototype-pollution",
        "name": "Client-Side Prototype Pollution",
    },
    "prototype pollution": {
        "template_id": "http/vulnerabilities/other/client-side-prototype-pollution.yaml",
        "tags": "prototype-pollution",
        "name": "Client-Side Prototype Pollution",
    },
    "sqli": {
        "template_id": "dast/vulnerabilities/sqli-error.yaml",
        "tags": "sqli",
        "name": "SQL Injection Error-Based",
    },
    "sql injection": {
        "template_id": "dast/vulnerabilities/sqli-error.yaml",
        "tags": "sqli",
        "name": "SQL Injection Error-Based",
    },
    "xss": {
        "template_id": "dast/vulnerabilities/xss-reflected.yaml",
        "tags": "xss",
        "name": "Reflected Cross-Site Scripting",
    },
    "cross-site scripting": {
        "template_id": "dast/vulnerabilities/xss-reflected.yaml",
        "tags": "xss",
        "name": "Reflected Cross-Site Scripting",
    },
    "ssrf": {
        "template_id": "dast/vulnerabilities/ssrf.yaml",
        "tags": "ssrf",
        "name": "Server-Side Request Forgery",
    },
    "idor": {
        "template_id": "http/vulnerabilities/generic/idor-check.yaml",
        "tags": "idor",
        "name": "Insecure Direct Object Reference",
    },
    "cors": {
        "template_id": "http/misconfiguration/cors/cors-arbitrary-origin.yaml",
        "tags": "cors",
        "name": "CORS Misconfiguration",
    },
    "open redirect": {
        "template_id": "http/vulnerabilities/generic/open-redirect.yaml",
        "tags": "redirect",
        "name": "Open Redirect",
    },
    "lfi": {
        "template_id": "dast/vulnerabilities/lfi.yaml",
        "tags": "lfi,traversal",
        "name": "Local File Inclusion",
    },
    "file upload": {
        "template_id": "dast/vulnerabilities/file-upload.yaml",
        "tags": "file-upload,upload",
        "name": "File Upload Vulnerability",
    },
    "file_upload": {
        "template_id": "dast/vulnerabilities/file-upload.yaml",
        "tags": "file-upload,upload",
        "name": "File Upload Vulnerability",
    },
    "path traversal": {
        "template_id": "dast/vulnerabilities/lfi.yaml",
        "tags": "lfi,traversal",
        "name": "Path Traversal",
    },
}


def get_nuclei_template_for_vuln(vuln_type: str) -> dict[str, str] | None:
    """Map a vulnerability hypothesis class to an existing official Nuclei template ID / tags."""
    if not vuln_type:
        return None
    v_norm = vuln_type.lower().strip().replace("-", " ").replace("_", " ")
    for k, v in NUCLEI_TEMPLATE_MAP.items():
        if k in v_norm or v_norm in k:
            return v
    return None
