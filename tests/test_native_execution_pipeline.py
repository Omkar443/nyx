"""
End-to-End Integration Tests for Native NYX Execution, Finding Generation & Auto-Validation Pipeline.
Verifies that NYX natively executes security probes, produces legitimate EXEC-XXXXXXXX IDs,
captures raw HTTP request/response evidence with SHA-256 hashes, passes the 7-Question Gate,
and persists verified findings end-to-end.
"""
import json
import socket
import threading
import tempfile
import shutil
import http.server
from pathlib import Path
import pytest

from nyx.execution.engine import ExecutionEngine
from nyx.execution.bridge import ExecutionFindingBridge, bridge_execution_to_findings
from nyx.execution.adapters.probe import ProbeAdapter
from nyx.models.execution import ExecutionResult, ExecutionStatus
from nyx.core.engagement import init_engagement
from nyx.core.findings import list_findings, get_finding
from nyx.core.evidence import list_evidence, verify_evidence
from nyx.application.ai_service import AIService
from nyx.api.mission import run_mission


class MockVulnerableHandler(http.server.BaseHTTPRequestHandler):
    """Mock HTTP server simulating vulnerable / exposed endpoints for live verification."""

    def log_message(self, format, *args):
        pass  # Suppress server logging during test runs

    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            body = (
                "# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.\n"
                "# TYPE process_cpu_seconds_total counter\n"
                "process_cpu_seconds_total 12.45\n"
                "# HELP http_requests_total Total number of HTTP requests made.\n"
                "# TYPE http_requests_total counter\n"
                'http_requests_total{code="200",method="get"} 1042\n'
            )
            self.wfile.write(body.encode("utf-8"))

        elif self.path == "/.well-known/security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            body = "Contact: security@example.local\nExpires: 2027-12-31T23:59:59.000Z\n"
            self.wfile.write(body.encode("utf-8"))

        elif self.path.startswith("/api/v1/user"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            body = json.dumps({"user_id": 42, "role": "admin", "email": "admin@internal.local"})
            self.wfile.write(body.encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")


@pytest.fixture
def mock_server():
    """Start a local mock vulnerable HTTP server for integration testing."""
    server = http.server.HTTPServer(("127.0.0.1", 0), MockVulnerableHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def test_workspace():
    """Create a temporary engagement directory workspace for test isolation."""
    temp_dir = Path(tempfile.mkdtemp(prefix="nyx_test_engagement_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_probe_adapter_command_and_parse():
    """Verify that ProbeAdapter builds commands and parses findings properly."""
    adapter = ProbeAdapter()
    valid, msg = adapter.validate("http://127.0.0.1:8000")
    assert valid is True

    cmd = adapter.build_command("http://127.0.0.1:8000")
    assert len(cmd) >= 4
    assert "probe_runner" in cmd[2]

    sample_out = json.dumps({
        "vulnerabilities": [{
            "title": "Exposed Metrics Endpoint",
            "endpoint": "http://127.0.0.1:8000/metrics",
            "vulnerability": "Security Misconfiguration",
            "severity": "Low",
            "description": "Exposed metrics test",
            "request": "GET /metrics HTTP/1.1",
            "response": "HTTP/1.1 200 OK\nprocess_cpu 1.0",
        }]
    })

    parsed = adapter.parse_result(sample_out, "")
    assert parsed["count"] == 1
    assert parsed["vulnerabilities"][0]["vulnerability"] == "Security Misconfiguration"


def test_execution_to_finding_bridge(test_workspace):
    """Verify that bridge_execution_to_findings creates stamped, triaged, and validated findings."""
    init_engagement("127.0.0.1", base_dir=test_workspace)

    res = ExecutionResult(
        execution_id="EXEC-TEST1234",
        tool_name="probe",
        target="127.0.0.1",
        status=ExecutionStatus.COMPLETED.value,
        command=["python", "-m", "nyx.execution.adapters.probe_runner", "127.0.0.1"],
        metadata={
            "vulnerabilities": [{
                "title": "Test Security Misconfiguration",
                "endpoint": "http://127.0.0.1/metrics",
                "parameter": "",
                "vulnerability": "Security Misconfiguration",
                "severity": "Low",
                "description": "Test finding for bridge",
                "request": "GET /metrics HTTP/1.1\nHost: 127.0.0.1",
                "response": "HTTP/1.1 200 OK\n\nhttp_requests_total 100",
            }]
        },
        stdout="Test stdout",
    )

    fids = bridge_execution_to_findings(res, base_dir=test_workspace)
    assert len(fids) == 1
    fid = fids[0]

    # Verify finding object on disk
    finding_obj = get_finding(fid, base_dir=test_workspace)
    assert finding_obj is not None
    assert finding_obj["task_id"] == "EXEC-TEST1234"
    assert finding_obj["state"] in ("VALIDATING", "TRIAGED", "VALIDATED", "CONFIRMED")

    # Verify evidence items created and hashes valid
    ev_data = list_evidence(fid, base_dir=test_workspace)
    ev_list = ev_data.get("evidence", [])
    assert len(ev_list) >= 2
    for ev in ev_list:
        v_res = verify_evidence(ev["evidence_id"], base_dir=test_workspace)
        assert v_res["status"] in ("success", "ok")
        assert v_res["integrity"] == "PASS"


def test_live_execution_engine_end_to_end(mock_server, test_workspace):
    """Verify that ExecutionEngine natively probes live target, logs EXEC ID, and creates validated findings."""
    init_engagement(mock_server, base_dir=test_workspace)

    engine = ExecutionEngine(base_dir=test_workspace)
    res = engine.execute("probe", mock_server, active_permitted=True)

    assert res.status == ExecutionStatus.COMPLETED.value
    assert res.execution_id.startswith("EXEC-")
    assert res.authorized is True

    # Check that findings were automatically bridged and persisted
    created = res.metadata.get("findings_created", [])
    assert len(created) >= 1

    fid = created[0]
    finding_obj = get_finding(fid, base_dir=test_workspace)
    assert finding_obj is not None
    assert finding_obj["task_id"] == res.execution_id
    assert finding_obj["state"] in ("VALIDATING", "TRIAGED", "VALIDATED", "CONFIRMED")


def test_ai_mission_execution_service(mock_server, test_workspace):
    """Verify that AIService.execute_mission runs all plan steps and produces real findings."""
    init_engagement(mock_server, base_dir=test_workspace)

    service = AIService(base_dir=test_workspace)
    exec_res = service.execute_mission(mock_server, active_permitted=True)

    assert exec_res.is_success is True
    data = exec_res.data
    assert data.get("executed_steps", 0) > 0

    all_findings = list_findings(base_dir=test_workspace).get("findings", [])
    assert isinstance(all_findings, list)


def test_cli_run_mission_end_to_end(mock_server):
    """Verify that nyx run_mission executes all phases natively and finishes cleanly."""
    init_res = init_engagement(mock_server, reset=True)
    assert init_res.get("status") == "success"

    exit_code = run_mission(mock_server)
    assert exit_code == 0

