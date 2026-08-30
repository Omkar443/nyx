import json
import pytest
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from pathlib import Path

from nyx.execution.adapters.ffuf import FfufAdapter
from nyx.recon.content_discovery import (
    probe_single_path,
    run_content_discovery,
    COMMON_CONTENT_WORDLIST,
)
from nyx.core.recon import (
    sync_recon_to_engagement,
    build_manifest,
    write_recon_summary,
)
from nyx.security.authorization import is_hostname_in_scope


class MockHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.sigma":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Server", "MockServer/1.0")
            self.end_headers()
            self.wfile.write(b"title: Suspicious Activity Sigma Rule")
        elif self.path == "/ftp/legal.md":
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown")
            self.send_header("Server", "MockServer/1.0")
            self.end_headers()
            self.wfile.write(b"# Legal Documentation and Terms")
        elif self.path == "/admin":
            self.send_response(403)
            self.send_header("Server", "MockServer/1.0")
            self.end_headers()
            self.wfile.write(b"Forbidden")
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Home</title></head><body>Welcome</body></html>")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        pass  # Quiet logs during test


class MockSpaHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = """<!DOCTYPE html>
            <html>
            <head>
              <title>SPA App</title>
              <script src="/static/js/main.bundle.js"></script>
            </head>
            <body><div id="root"></div></body>
            </html>"""
            self.wfile.write(html.encode("utf-8"))
        elif self.path == "/static/js/main.bundle.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            js = """
            const ENDPOINTS = {
                SIGNUP: "api/auth/signup",
                RESET_PASSWORD: "/api/v2/user/reset-password",
                CHECK_OTP: "api/auth/v3/check-otp",
                ORDERS: "/workshop/api/shop/orders",
                COUPON: "api/v2/coupon/validate-coupon",
                VIDEOS: "/api/v2/user/videos/convert_video"
            };
            function fetchUser() { return fetch("/api/v2/user/dashboard"); }
            """
            self.wfile.write(js.encode("utf-8"))
        elif self.path == "/.sigma":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"sigma-rule-content")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(("127.0.0.1", 0), MockHttpHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def mock_spa_server():
    server = HTTPServer(("127.0.0.1", 0), MockSpaHttpHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_ffuf_adapter_validation_and_build():
    adapter = FfufAdapter()
    ok, msg = adapter.validate("http://example.com")
    assert ok is True
    assert adapter.tool_name == "ffuf"

    cmd = adapter.build_command("http://example.com")
    assert any("ffuf" in c for c in cmd)
    assert "-u" in cmd
    assert "http://example.com/FUZZ" in cmd
    assert "-json" in cmd


def test_ffuf_adapter_parse_result():
    adapter = FfufAdapter()
    mock_json_out = json.dumps({
        "results": [
            {"url": "http://example.com/.sigma", "status": 200, "length": 45},
            {"url": "http://example.com/admin", "status": 403, "length": 12}
        ]
    })
    res = adapter.parse_result(mock_json_out, "")
    assert res["parsed"] is True
    assert res["count"] == 2
    assert "http://example.com/.sigma" in res["endpoints"]
    assert res["results"][0]["source"] == "content_discovery"


def test_run_content_discovery_finds_unlinked_paths(mock_server, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".engagement").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".engagement" / "authorization.yaml").write_text("authorized: true\nscope: [127.0.0.1]\n", encoding="utf-8")
    (tmp_path / ".engagement" / "target.yaml").write_text("target: 127.0.0.1\nscope: [127.0.0.1]\n", encoding="utf-8")

    test_wordlist = [".sigma", "ftp/legal.md", "admin", "non_existent_file.xyz"]
    discovered = run_content_discovery([mock_server], wordlist=test_wordlist, max_workers=2)

    found_paths = [d["path"] for d in discovered]
    assert "/.sigma" in found_paths
    assert "/ftp/legal.md" in found_paths
    assert "/admin" in found_paths
    assert "/non_existent_file.xyz" not in found_paths

    for d in discovered:
        assert d["source"] == "content_discovery"
        assert d["discovery_method"] == "wordlist_probe"


def test_sync_recon_to_engagement_with_content_discovery(tmp_path):
    eng_dir = tmp_path / ".engagement"
    eng_dir.mkdir(parents=True, exist_ok=True)

    subs = {"target.com", "api.target.com"}
    resolved = {"target.com": ["192.168.1.1"], "api.target.com": ["192.168.1.2"]}
    live = [{"host": "target.com", "url": "https://target.com", "code": 200, "server": "nginx"}]
    content_discovered = [
        {"url": "https://target.com/.sigma", "path": "/.sigma", "status": 200, "server": "nginx", "discovery_method": "wordlist_probe"}
    ]

    total, new_cnt, known = sync_recon_to_engagement(
        "target.com", subs, resolved, live, content_discovered=content_discovered, base_dir=tmp_path
    )

    assert total == 4
    assert new_cnt == 3

    ep_file = eng_dir / "endpoints.json"
    assert ep_file.exists()
    endpoints = json.loads(ep_file.read_text(encoding="utf-8"))

    sigma_ep = next((e for e in endpoints if "/.sigma" in e["url"]), None)
    assert sigma_ep is not None
    assert sigma_ep["source"] == "content_discovery"
    assert "content_discovery" in sigma_ep["sources"]
    assert sigma_ep["discovery_method"] == "wordlist_probe"


def test_build_manifest_and_summary_with_content_discovery(tmp_path):
    subs = {"target.com"}
    resolved = {"target.com": ["192.168.1.1"]}
    live = [{"host": "target.com", "url": "https://target.com", "code": 200, "server": "nginx"}]
    content_discovered = [
        {"url": "https://target.com/ftp/legal.md", "path": "/ftp/legal.md", "status": 200, "server": "nginx", "discovery_method": "wordlist_probe"}
    ]

    manifest = build_manifest("target.com", subs, resolved, live, content_discovered=content_discovered)
    assert manifest["counts"]["content_discovered"] == 1
    assert len(manifest["content_discovery"]) == 1

    summary_file = tmp_path / "RECON_SUMMARY.md"
    write_recon_summary("target.com", subs, resolved, live, summary_file, content_discovered=content_discovered)
    content = summary_file.read_text(encoding="utf-8")
    assert "## Content discovery (unlinked paths)" in content
    assert "https://target.com/ftp/legal.md" in content


def test_extract_spa_routes_from_html_and_js_bundle(mock_spa_server, tmp_path, monkeypatch):
    """Test SPA crawler extracting API endpoints from JS bundles."""
    from nyx.recon.content_discovery import extract_spa_routes
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".engagement").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".engagement" / "authorization.yaml").write_text("authorized: true\nscope: ['127.0.0.1']\n", encoding="utf-8")
    (tmp_path / ".engagement" / "target.yaml").write_text("target: 127.0.0.1\nscope: ['127.0.0.1']\n", encoding="utf-8")

    discovered = extract_spa_routes(mock_spa_server)
    paths = [d["path"] for d in discovered]

    assert "/api/auth/signup" in paths
    assert "/api/v2/user/reset-password" in paths
    assert "/api/auth/v3/check-otp" in paths
    assert "/workshop/api/shop/orders" in paths
    assert "/api/v2/coupon/validate-coupon" in paths
    assert "/api/v2/user/videos/convert_video" in paths
    assert "/api/v2/user/dashboard" in paths

    for d in discovered:
        assert d["source"] == "content_discovery"
        assert d["discovery_method"] in ("spa_js_bundle_extraction", "spa_html_inline")


def test_run_content_discovery_integrates_spa_and_wordlist(mock_spa_server, tmp_path, monkeypatch):
    """Test unified run_content_discovery combining SPA extraction and wordlist fuzzing."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".engagement").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".engagement" / "authorization.yaml").write_text("authorized: true\nscope: ['127.0.0.1']\n", encoding="utf-8")
    (tmp_path / ".engagement" / "target.yaml").write_text("target: 127.0.0.1\nscope: ['127.0.0.1']\n", encoding="utf-8")

    discovered = run_content_discovery([mock_spa_server], wordlist=[".sigma", "nonexistent.file"], max_workers=2)
    paths = [d["path"] for d in discovered]

    # Wordlist route
    assert "/.sigma" in paths
    # SPA JS-extracted routes
    assert "/api/auth/signup" in paths
    assert "/workshop/api/shop/orders" in paths

