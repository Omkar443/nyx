import time
import pytest
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from typing import Any

from nyx.recon.content_discovery import (
    should_skip_content_discovery,
    extract_spa_routes,
    run_content_discovery,
)


def test_should_skip_content_discovery_filtering():
    """Verify smart scope and host filtering for non-web, CDN, telemetry, storage, and dead hosts."""
    # CDN & static assets
    skip, reason = should_skip_content_discovery("https://cdn-design.tesla.com")
    assert skip is True
    assert "CDN" in reason

    skip, reason = should_skip_content_discovery("https://static-assets-teslaaccount.tesla.com")
    assert skip is True
    assert "CDN" in reason

    skip, reason = should_skip_content_discovery("https://digitalassets-learning.tesla.com")
    assert skip is True
    assert "CDN" in reason

    # Telemetry & streaming
    skip, reason = should_skip_content_discovery("https://gateway-public-telemetry-prd5b-fleet.prd.vn.cloud.tesla.com")
    assert skip is True
    assert "Telemetry" in reason

    skip, reason = should_skip_content_discovery("https://fleetview.europe.fn.tesla.com")
    assert skip is True
    assert "Telemetry" in reason

    skip, reason = should_skip_content_discovery("https://live-data.fn.tesla.com")
    assert skip is True
    assert "Telemetry" in reason

    # Object storage
    skip, reason = should_skip_content_discovery("https://s3.eng.na.vn.cloud.tesla.com")
    assert skip is True
    assert "Storage" in reason

    skip, reason = should_skip_content_discovery("https://vehicle-files.eng.euw1.vn.cloud.tesla.com")
    assert skip is True
    assert "Storage" in reason

    # Dead origin via metadata
    skip, reason = should_skip_content_discovery("https://akamai-gateway.tesla.com", metadata={"code": 503})
    assert skip is True
    assert "503" in reason

    skip, reason = should_skip_content_discovery("https://broken.tesla.com", metadata={"code": 502})
    assert skip is True
    assert "502" in reason

    # Legitimate web applications & APIs must NOT be skipped
    skip, _ = should_skip_content_discovery("https://auth.tesla.com", metadata={"code": 200})
    assert skip is False

    skip, _ = should_skip_content_discovery("https://repair.tesla.com", metadata={"code": 200})
    assert skip is False

    skip, _ = should_skip_content_discovery("https://sso-dev.tesla.com", metadata={"code": 404})
    assert skip is False

    skip, _ = should_skip_content_discovery("https://fleet-api.prd.usw.vn.cloud.tesla.com", metadata={"code": 200})
    assert skip is False


class MultiScriptMockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = """<!DOCTYPE html>
            <html>
            <head>
              <script src="/js/app.bundle.js"></script>
              <script src="/js/vendor.chunk.js"></script>
              <script src="/js/runtime.js"></script>
            </head>
            <body></body>
            </html>"""
            self.wfile.write(html.encode("utf-8"))
        elif self.path == "/js/app.bundle.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'const route1 = "/api/v1/checkout";')
        elif self.path == "/js/vendor.chunk.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'const route2 = "/api/v2/vehicles";')
        elif self.path == "/js/runtime.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'const route3 = "/identity/token";')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def multi_script_server():
    server = HTTPServer(("127.0.0.1", 0), MultiScriptMockHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_concurrent_js_bundle_extraction(multi_script_server, tmp_path, monkeypatch):
    """Verify concurrent JS bundle fetching extracts all routes correctly."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".engagement").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".engagement" / "authorization.yaml").write_text("authorized: true\nscope: ['127.0.0.1']\n", encoding="utf-8")
    (tmp_path / ".engagement" / "target.yaml").write_text("target: 127.0.0.1\nscope: ['127.0.0.1']\n", encoding="utf-8")

    routes = extract_spa_routes(multi_script_server, timeout=3, max_scripts=5)
    paths = [r["path"] for r in routes]

    assert "/api/v1/checkout" in paths
    assert "/api/v2/vehicles" in paths
    assert "/identity/token" in paths


def test_intra_loop_progress_callback_and_endpoint_budget(multi_script_server, tmp_path, monkeypatch):
    """Verify intra-loop tracker progress reporting and per-endpoint budget enforcement."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".engagement").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".engagement" / "authorization.yaml").write_text("authorized: true\nscope: ['127.0.0.1']\n", encoding="utf-8")
    (tmp_path / ".engagement" / "target.yaml").write_text("target: 127.0.0.1\nscope: ['127.0.0.1']\n", encoding="utf-8")

    progress_events = []

    def mock_progress_cb(idx: int, total: int, base: str, found_cnt: int, status_note: str = ""):
        progress_events.append({
            "idx": idx,
            "total": total,
            "base": base,
            "found_cnt": found_cnt,
            "status_note": status_note,
        })

    endpoints = [
        multi_script_server,
        "https://cdn.example.com",  # Should be skipped
    ]

    t0 = time.time()
    discovered = run_content_discovery(
        endpoints,
        wordlist=[".env", "admin"],
        max_workers=2,
        timeout=2,
        endpoint_budget_seconds=3.0,
        progress_callback=mock_progress_cb,
    )
    elapsed = time.time() - t0

    # Total duration should be well under 5 seconds
    assert elapsed < 5.0

    # Events should be recorded for both endpoints
    assert len(progress_events) >= 2
    # First endpoint (probed)
    assert any(e["idx"] == 0 and "Probing" in e["status_note"] for e in progress_events)
    # Second endpoint (skipped by CDN filter)
    assert any(e["idx"] == 1 and "Skipped" in e["status_note"] for e in progress_events)


def test_detect_uniform_waf_block_logic():
    """Verify uniform WAF block detection heuristics."""
    from nyx.recon.content_discovery import detect_uniform_waf_block

    # 1. 20 probes returning 403 -> WAF uniform block
    probes_403 = [{"url": f"https://example.com/p{i}", "status": 403} for i in range(20)]
    is_waf, code = detect_uniform_waf_block(probes_403)
    assert is_waf is True
    assert code == 403

    # 2. 1 probe returning 403 (e.g. genuine /admin) -> Not WAF block
    single_403 = [{"url": "https://example.com/admin", "status": 403}]
    is_waf, code = detect_uniform_waf_block(single_403)
    assert is_waf is False
    assert code is None

    # 3. 10 probes returning 200 OK -> Not WAF block
    probes_200 = [{"url": f"https://example.com/p{i}", "status": 200} for i in range(10)]
    is_waf, code = detect_uniform_waf_block(probes_200)
    assert is_waf is False

    # 4. Mixed: 18 probes returning 429 (rate-limit / IP block) + 2 returning 200 -> WAF block 429
    mixed_429 = [{"url": f"https://example.com/p{i}", "status": 429} for i in range(18)] + [
        {"url": "https://example.com/home", "status": 200},
        {"url": "https://example.com/login", "status": 200},
    ]
    is_waf, code = detect_uniform_waf_block(mixed_429)
    assert is_waf is True
    assert code == 429

    # 5. Base URL meta was 403, and all 6 returned probes are 403 -> WAF block
    base_403_probes = [{"url": f"https://example.com/p{i}", "status": 403} for i in range(6)]
    is_waf, code = detect_uniform_waf_block(base_403_probes, meta={"code": 403})
    assert is_waf is True
    assert code == 403


class Blanket403MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Simulates a blanket WAF returning 403 for everything
        if self.path == "/real-api":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "AkamaiGHost")
            self.end_headers()
            self.wfile.write(b"Access Denied")

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def blanket_403_server():
    server = HTTPServer(("127.0.0.1", 0), Blanket403MockHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_waf_blocking_false_positive_filtering_integration(blanket_403_server, tmp_path, monkeypatch):
    """Verify that a blanket 403 WAF response is detected and false-positive 403s are discarded."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".engagement").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".engagement" / "authorization.yaml").write_text("authorized: true\nscope: ['127.0.0.1']\n", encoding="utf-8")
    (tmp_path / ".engagement" / "target.yaml").write_text("target: 127.0.0.1\nscope: ['127.0.0.1']\n", encoding="utf-8")

    # Wordlist with 10 paths that will all hit the blanket 403, plus one real-api path that returns 200
    wordlist = [
        "admin", ".env", ".git/HEAD", ".git/config", "swagger.json",
        "graphql", "backup.sql", "config.json", "web.config", "actuator",
        "real-api"
    ]

    discovered = run_content_discovery([blanket_403_server], wordlist=wordlist, max_workers=2, timeout=2)
    paths = [d["path"] for d in discovered]

    # The real-api path (200 OK) must be kept
    assert "/real-api" in paths
    # The 10 blanket 403s must be discarded as WAF false-positives
    assert "/admin" not in paths
    assert "/.env" not in paths
    assert "/.git/HEAD" not in paths
    assert "/swagger.json" not in paths


def test_subfinder_timeout_configurable_and_partial_capture(tmp_path, monkeypatch):
    """Verify subfinder timeout configuration and partial output recovery on timeout."""
    from nyx.core.recon import recon_subdomains_via_subfinder
    from pathlib import Path

    # 1. Verify default timeout is 180s when env var is unset
    monkeypatch.delenv("NYX_SUBFINDER_TIMEOUT", raising=False)
    captured_timeout = []

    def mock_run_cmd(cmd, timeout=30):
        captured_timeout.append(timeout)
        return 0, "api.example.com\n", ""

    monkeypatch.setattr("nyx.core.recon.has_cmd", lambda name: True)
    monkeypatch.setattr("nyx.core.recon.run_cmd", mock_run_cmd)

    subs = recon_subdomains_via_subfinder("example.com")
    assert captured_timeout[0] == 180
    assert "api.example.com" in subs

    # 2. Verify configurable timeout via env var
    monkeypatch.setenv("NYX_SUBFINDER_TIMEOUT", "240")
    captured_timeout.clear()
    recon_subdomains_via_subfinder("example.com")
    assert captured_timeout[0] == 240

    # 3. Verify partial output recovery from -o file on timeout
    def mock_run_cmd_timeout(cmd, timeout=30):
        # Locate the -o output path in cmd
        if "-o" in cmd:
            out_idx = cmd.index("-o") + 1
            out_file = Path(cmd[out_idx])
            # Simulate subfinder writing 3 subdomains before being killed by timeout
            out_file.write_text("sub1.example.com\nsub2.example.com\nsub3.example.com\n", encoding="utf-8")
        # Return timeout error code with empty stdout
        return 124, "", "timeout"

    monkeypatch.setattr("nyx.core.recon.run_cmd", mock_run_cmd_timeout)
    recovered_subs = recon_subdomains_via_subfinder("example.com")
    assert "sub1.example.com" in recovered_subs
    assert "sub2.example.com" in recovered_subs
    assert "sub3.example.com" in recovered_subs


def test_crtsh_timeout_configurable_and_retries(monkeypatch):
    """Verify crt.sh timeout configuration and retry resiliency."""
    import json
    from nyx.core.recon import recon_subdomains_via_crtsh

    monkeypatch.setenv("NYX_CRTSH_TIMEOUT", "45")

    calls = []
    def mock_http_get(url, timeout=5, headers=None):
        calls.append((url, timeout))
        if len(calls) == 1:
            # First attempt fails (e.g. crt.sh temporary 503)
            return 503, {}, ""
        # Second attempt succeeds
        mock_data = [{"name_value": "app.example.com\nmail.example.com"}]
        return 200, {}, json.dumps(mock_data)

    monkeypatch.setattr("nyx.core.recon.http_get", mock_http_get)
    monkeypatch.setattr("time.sleep", lambda s: None)

    subs = recon_subdomains_via_crtsh("example.com", retries=1)
    assert len(calls) == 2
    assert calls[0][1] == 45  # Confirms NYX_CRTSH_TIMEOUT was used
    assert "app.example.com" in subs
    assert "mail.example.com" in subs

