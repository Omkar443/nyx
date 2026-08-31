"""
NYX FFUF Tool Adapter
Specialized execution and output parsing adapter for FFUF web directory and content discovery.
"""
from __future__ import annotations

import collections
import json
import re
from typing import Any
from nyx.execution.adapters.base import ToolAdapter
from nyx.infrastructure.tools import get_tool_executable_vector


FILE_SIGNATURE_PATTERNS = {
    "passwd": [
        re.compile(r"root:[*!x]:0:0:", re.IGNORECASE),
        re.compile(r"root:x:0:0", re.IGNORECASE),
        re.compile(r"\b(?:bin|daemon|sys|nobody|www-data):[*!x]:\d+:\d+:", re.IGNORECASE),
        re.compile(r":/(?:bin|sbin|usr/bin|nonexistent):/(?:bin/|usr/bin/)?(?:bash|sh|zsh|nologin|false)", re.IGNORECASE),
    ],
    "shadow": [
        re.compile(r"root:\$[156y]\$[a-zA-Z0-9./]+", re.IGNORECASE),
        re.compile(r"root:[*!]:\d+:\d+:\d+:\d+:::", re.IGNORECASE),
        re.compile(r"\b(?:daemon|bin|sys):[*!]:", re.IGNORECASE),
    ],
    "boot.ini": [
        re.compile(r"\[boot loader\]", re.IGNORECASE),
        re.compile(r"\[operating systems\]", re.IGNORECASE),
        re.compile(r"multi\(\d+\)disk\(\d+\)rdisk\(\d+\)partition\(\d+\)", re.IGNORECASE),
    ],
    "win.ini": [
        re.compile(r"\[fonts\]", re.IGNORECASE),
        re.compile(r"\[extensions\]", re.IGNORECASE),
        re.compile(r"\[files\]", re.IGNORECASE),
        re.compile(r"\[mci extensions\]", re.IGNORECASE),
    ],
    "access.log": [
        re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-\s+.*\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}", re.IGNORECASE),
        re.compile(r"\"(?:GET|POST|HEAD|OPTIONS|PUT|DELETE)\s+[^\"\n]+\s+HTTP/\d\.\d\"\s+\d{3}\s+\d+", re.IGNORECASE),
        re.compile(r"\"\s+\d{3}\s+\d+\s+\"[^\"]*\"\s+\"[^\"]*\"", re.IGNORECASE),
    ],
    "error.log": [
        re.compile(r"\[[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\d{4}\]\s+\[(?:error|warn|notice|crit|alert|emerg)\]", re.IGNORECASE),
        re.compile(r"\[client\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\]", re.IGNORECASE),
        re.compile(r"PHP (?:Fatal error|Warning|Notice|Parse error):", re.IGNORECASE),
    ],
    "environ": [
        re.compile(r"\b(?:PATH|HTTP_USER_AGENT|DOCUMENT_ROOT|SERVER_SOFTWARE|GATEWAY_INTERFACE)=", re.IGNORECASE),
        re.compile(r"\b(?:SHELL|PWD|USER|HOME|LANG)=", re.IGNORECASE),
    ],
}


def verify_file_signature(url: str, body: str) -> tuple[bool, str]:
    """Deterministically verifies whether a response body matches expected signatures for known target files."""
    if not body or not isinstance(body, str):
        return True, "No body content provided to verify"

    url_lower = url.lower()
    for sig_key, patterns in FILE_SIGNATURE_PATTERNS.items():
        if sig_key in url_lower:
            if any(pat.search(body) for pat in patterns):
                return True, f"Verified empirical signature for {sig_key}"
            return False, f"Failed signature check: response body does not contain expected {sig_key} patterns"

    return True, "No specific signature requirement for generic target"


class FfufAdapter(ToolAdapter):
    tool_name = "ffuf"

    def validate(self, target: str, arguments: list[str] | None = None) -> tuple[bool, str]:
        if not target or not isinstance(target, str):
            return False, "Target must be a non-empty target URL."
        return True, "Valid"

    def build_command(self, target: str, arguments: list[str] | None = None) -> list[str]:
        target_url = target.rstrip("/")
        if "FUZZ" not in target_url:
            target_url = f"{target_url}/FUZZ"

        tool_vec = get_tool_executable_vector("ffuf") or ["ffuf"]
        cmd = list(tool_vec)
        args_list = list(arguments) if arguments else []

        if "-u" not in args_list:
            cmd.extend(["-u", target_url])
        if "-json" not in args_list:
            cmd.append("-json")

        has_regex = ("-mr" in args_list or "-mr" in cmd)
        has_status = ("-mc" in args_list or "-mc" in cmd)

        # If a regex matcher (-mr) is specified, do NOT add status code matcher (-mc) by default.
        # This prevents ffuf's default OR matcher logic from matching all HTTP 200 responses.
        if not has_regex and not has_status:
            cmd.extend(["-mc", "200,204,301,302,307,401,403"])

        cmd.extend(args_list)

        # If a regex matcher is present, enforce -mmode and so that any combined matchers must strictly conjugate
        if "-mmode" not in cmd and (has_regex or "-mr" in cmd):
            cmd.extend(["-mmode", "and"])

        if "-w" not in cmd:
            cmd.extend(["-w", "/usr/share/seclists/Discovery/Web-Content/common.txt"])

        return cmd

    def parse_result(self, stdout: str, stderr: str) -> dict[str, Any]:
        endpoints = []
        raw_items = []
        parsed = False

        try:
            data = json.loads(stdout)
            raw_items = data.get("results", [])
            parsed = True
        except Exception:
            for line in stdout.splitlines():
                line_str = line.strip()
                if line_str.startswith("{"):
                    try:
                        res = json.loads(line_str)
                        if res.get("url"):
                            raw_items.append(res)
                        parsed = True
                    except Exception:
                        pass

        # 1. Compute baseline response distribution (words, lines, length) to identify soft-200 wildcards
        baseline_stats = None
        if len(raw_items) >= 5:
            combos = []
            for r in raw_items:
                st = r.get("status")
                w = r.get("words", 0)
                l = r.get("lines", 0)
                combos.append((st, w, l))
            most_common_combo, count = collections.Counter(combos).most_common(1)[0]
            if count / len(raw_items) >= 0.40:
                matching_lengths = [r.get("length", 0) for r in raw_items if (r.get("status"), r.get("words", 0), r.get("lines", 0)) == most_common_combo]
                base_len = collections.Counter(matching_lengths).most_common(1)[0][0] if matching_lengths else 0
                baseline_stats = {
                    "status": most_common_combo[0],
                    "words": most_common_combo[1],
                    "lines": most_common_combo[2],
                    "base_length": base_len,
                    "dominance_ratio": count / len(raw_items),
                }

        vulnerabilities = []
        for res in raw_items:
            ep = res.get("url")
            if not ep:
                continue

            item = {
                "url": ep,
                "status": res.get("status"),
                "length": res.get("length"),
                "words": res.get("words"),
                "lines": res.get("lines"),
                "source": "content_discovery",
            }
            endpoints.append(item)

            # Check if this request is a security probe
            is_vuln_probe = any(pat in ep.lower() for pat in ["passwd", "shadow", "boot.ini", "win.ini", "access.log", "error.log", "environ", "../", "..\\", "%2e%2e"])
            if not is_vuln_probe or res.get("status") not in (200, 301, 302, 307):
                continue

            # 2. Check deterministic file signatures if response body or snippet is available
            body = res.get("body") or res.get("body_sample") or res.get("response") or ""
            if body:
                sig_ok, sig_reason = verify_file_signature(ep, body)
                if not sig_ok:
                    # Explicitly rejected by deterministic content signature check
                    continue

            # 3. Baseline response diffing: discard matches that mirror the dominant wildcard/template response
            if baseline_stats:
                st = res.get("status")
                w = res.get("words", 0)
                l = res.get("lines", 0)
                length = res.get("length", 0)

                is_same_structure = (st == baseline_stats["status"] and w == baseline_stats["words"] and l == baseline_stats["lines"])
                is_same_len = abs(length - baseline_stats["base_length"]) <= (len(ep) + 40)

                if is_same_structure and is_same_len and not body:
                    # Rejected: response matches generic application template baseline
                    continue

            vulnerabilities.append({
                "title": f"Potential Path Disclosure / Fuzz Match: {ep}",
                "endpoint": ep,
                "status": res.get("status"),
                "length": res.get("length"),
                "words": res.get("words"),
                "lines": res.get("lines"),
            })

        ep_urls = [e["url"] if isinstance(e, dict) else e for e in endpoints]
        return {
            "endpoints": sorted(list(set(ep_urls))),
            "results": endpoints,
            "vulnerabilities": vulnerabilities,
            "count": len(endpoints),
            "assets_found": len(endpoints),
            "parsed": parsed,
            "baseline_stats": baseline_stats,
        }

