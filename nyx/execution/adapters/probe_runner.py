"""
NYX Native HTTP Probe Runner Entrypoint
Executes targeted HTTP vulnerability checks against authorized targets.
"""
import sys
import json
import urllib.request
import urllib.error
import urllib.parse


def run_probes(target: str):
    if not target.startswith("http://") and not target.startswith("https://"):
        target_url = f"http://{target}"
    else:
        target_url = target

    vulnerabilities = []

    # Probe 1: Exposed Metrics / Telemetry
    try:
        req = urllib.request.Request(f"{target_url}/metrics", headers={"User-Agent": "NYX-Security-Probe/1.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            body = res.read().decode('utf-8', errors='replace')
            if res.getcode() == 200 and ("http_requests" in body or "process_cpu" in body or "go_gc" in body):
                vulnerabilities.append({
                    "title": "Exposed Metrics Endpoint Leaking Real-Time System Telemetry",
                    "endpoint": f"{target_url}/metrics",
                    "parameter": "",
                    "vulnerability": "Security Misconfiguration",
                    "severity": "Low",
                    "tag": "cloud-misconfig",
                    "description": "Public unauthenticated access to /metrics exposes internal memory and traffic metrics.",
                    "request": f"GET /metrics HTTP/1.1\nHost: {urllib.parse.urlparse(target_url).netloc}\nUser-Agent: NYX-Security-Probe/1.0",
                    "response": f"HTTP/1.1 200 OK\n\n{body[:1500]}",
                })
    except Exception:
        pass

    # Probe 2: Public Security.txt Policy
    try:
        req = urllib.request.Request(f"{target_url}/.well-known/security.txt", headers={"User-Agent": "NYX-Security-Probe/1.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            body = res.read().decode('utf-8', errors='replace')
            if res.getcode() == 200 and "Contact:" in body:
                vulnerabilities.append({
                    "title": "Security Policy File Disclosure (.well-known/security.txt)",
                    "endpoint": f"{target_url}/.well-known/security.txt",
                    "parameter": "",
                    "vulnerability": "Information Disclosure",
                    "severity": "Low",
                    "tag": "tls-network",
                    "description": "Public .well-known/security.txt policy file discloses contact emails.",
                    "request": f"GET /.well-known/security.txt HTTP/1.1\nHost: {urllib.parse.urlparse(target_url).netloc}",
                    "response": f"HTTP/1.1 200 OK\n\n{body[:1500]}",
                })
    except Exception:
        pass

    # Output JSON line for adapter parsing
    output = {"vulnerabilities": vulnerabilities, "target": target_url}
    print(json.dumps(output))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_probes(sys.argv[1])
    else:
        print(json.dumps({"vulnerabilities": []}))
