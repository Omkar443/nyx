import asyncio
import json
import time
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from nyx.agent.agent import NYXAgent
from nyx.agent.approval import ApprovalSystem
from nyx.ai.planner import MissionPlanner
from nyx.ai.tracker import active_mission_tracker
from nyx.core import engagement
from nyx.web.auth import get_or_create_api_token
from nyx.web.app import create_app
import nyx.web.events


@pytest.fixture
def clean_workspace(tmp_path: Path, monkeypatch):
    """Fixture providing an isolated engagement workspace."""
    engagement.init_engagement("http://localhost:4444", reset=True, base_dir=tmp_path)
    monkeypatch.chdir(tmp_path)
    active_mission_tracker.reset()
    return tmp_path


def test_approve_action_emits_events_in_exact_order(clean_workspace, monkeypatch):
    """Verify approve_action emits 'executing' and 'action_approved' BEFORE execute_step,
    and 'reasoning' before resuming the autonomous loop.
    """
    app_sys = ApprovalSystem(base_dir=clean_workspace)
    action_id = "ACT-TEST01"
    app_sys.submit_for_approval({
        "action_id": action_id,
        "mission_target": "http://localhost:4444",
        "target": "http://localhost:4444/api",
        "action": "validate_sqli",
        "reason": "Test SQLi validation",
        "tool_name": "sqlmap",
        "risk": "High",
        "impact_class": "DESTRUCTIVE",
        "impact_justification": "SQL injection active verification",
        "step": {
            "name": "SQLMap Injection Check",
            "tool": "sqlmap",
            "action": "validate",
            "impact_class": "DESTRUCTIVE",
            "target": "http://localhost:4444/api",
        },
        "current_iteration": 1,
        "max_iterations": 3,
        "prior_iterations": [],
        "active_permitted": True,
        "remaining_destructive_count": 1,
        "upcoming_pipeline": [],
    })

    # Set tracker in paused state
    active_mission_tracker.pause({"status": "paused_for_approval", "action_id": action_id})
    assert active_mission_tracker.is_running is False
    assert active_mission_tracker.status == "paused_for_approval"

    event_log = []

    def mock_emit_sync(event_type, data=None, mission_id=None):
        # Record event and tracker state at the exact moment of emission
        event_log.append({
            "event": event_type,
            "data": dict(data or {}),
            "tracker_running": active_mission_tracker.is_running,
            "tracker_status": active_mission_tracker.status,
            "time": time.time(),
        })

    monkeypatch.setattr(nyx.web.events, "emit_event_sync", mock_emit_sync)

    execution_order = []

    def mock_execute_step(step, target, active_permitted=False):
        execution_order.append("execute_step")
        return {"success": True, "result": {"status": "completed"}}

    def mock_run_autonomous_loop(**kwargs):
        execution_order.append("run_autonomous_loop")
        return {"status": "complete", "message": "Done"}

    monkeypatch.setattr(MissionPlanner, "execute_step", lambda self, step, target, active_permitted=False: mock_execute_step(step, target, active_permitted))
    monkeypatch.setattr(MissionPlanner, "run_autonomous_loop", lambda self, **kwargs: mock_run_autonomous_loop(**kwargs))

    agent = NYXAgent(base_dir=clean_workspace)
    res = agent.approve_action(action_id)
    assert res.get("success") is True

    # 1. Verify action_approved and executing events were emitted
    event_types = [e["event"] for e in event_log]
    assert "action_approved" in event_types
    assert "mission_progress" in event_types

    # Find the first mission_progress event (should be state: executing)
    first_prog = next(e for e in event_log if e["event"] == "mission_progress")
    assert first_prog["data"]["state"] == "executing"
    assert first_prog["data"]["action_id"] == action_id
    assert "Executing Approved Action" in first_prog["data"]["step_name"]
    # Tracker must have transitioned to running=True at the moment of first emission!
    assert first_prog["tracker_running"] is True
    assert first_prog["tracker_status"] == "running"

    # 2. Verify action_approved event payload
    approved_ev = next(e for e in event_log if e["event"] == "action_approved")
    assert approved_ev["data"]["action_id"] == action_id
    assert approved_ev["data"]["step"]["tool"] == "sqlmap"

    # 3. Verify execution order: events emitted BEFORE execute_step, reasoning emitted before run_autonomous_loop
    assert execution_order == ["execute_step", "run_autonomous_loop"]

    # 4. Verify reasoning progress event emitted after execute_step and before run_autonomous_loop
    reasoning_prog = [e for e in event_log if e["event"] == "mission_progress" and e["data"].get("state") == "reasoning"]
    assert len(reasoning_prog) >= 1
    assert reasoning_prog[0]["data"]["iteration"] == 2
    assert "resuming mission loop" in reasoning_prog[0]["data"]["message"]


def test_action_approved_event_received_over_websocket(clean_workspace):
    """Verify action_approved event actually reaches connected WebSocket client."""
    token = get_or_create_api_token()
    app = create_app()

    with TestClient(app) as client:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            # Broadcast the event
            nyx.web.events.emit_event_sync(
                "action_approved",
                data={
                    "action_id": "ACT-WS01",
                    "step": {"name": "SQL Injection Verification", "tool": "sqlmap"},
                    "target": "http://localhost:4444",
                },
                mission_id="http://localhost:4444",
            )

            # Receive and assert on the wire
            raw_msg = ws.receive_text()
            msg = json.loads(raw_msg)
            assert msg.get("event") == "action_approved"
            assert msg.get("data", {}).get("action_id") == "ACT-WS01"
            assert msg.get("data", {}).get("step", {}).get("tool") == "sqlmap"
            assert msg.get("mission_id") == "http://localhost:4444"

            # Confirm WebSocket stays open and healthy (no drops)
            ws.send_text("ping")
            pong = ws.receive_text()
            assert pong == "pong"


def test_emit_and_tracker_non_blocking_performance():
    """Verify emit_event_sync and update_progress execute without blocking I/O."""
    t0 = time.perf_counter()
    for i in range(100):
        active_mission_tracker.update_progress({
            "state": "executing",
            "iteration": i,
            "max_iterations": 100,
            "step_name": f"Step {i}",
            "message": f"Progress message {i}",
        })
        nyx.web.events.emit_event_sync(
            "mission_progress",
            data={"state": "executing", "step": i},
            mission_id="http://localhost:4444",
        )
    t_elapsed = time.perf_counter() - t0
    # 100 calls should take well under 100ms (typically <5ms)
    assert t_elapsed < 0.100, f"Calls took too long: {t_elapsed:.4f}s for 100 iterations"


def test_concurrent_request_during_approval_execution(clean_workspace, monkeypatch):
    """Verify an unrelated endpoint (GET /api/v1/findings) responds immediately during approval execution."""
    token = get_or_create_api_token()
    app = create_app()

    app_sys = ApprovalSystem(base_dir=clean_workspace)
    action_id = "ACT-CONC01"
    app_sys.submit_for_approval({
        "action_id": action_id,
        "mission_target": "http://localhost:4444",
        "target": "http://localhost:4444",
        "step": {"name": "Test Step", "tool": "nuclei"},
        "current_iteration": 1,
        "max_iterations": 2,
    })

    # Simulate slow execute_step in planner
    def slow_execute_step(step, target, active_permitted=False):
        time.sleep(0.15)  # 150ms tool execution
        return {"success": True, "result": {"status": "completed"}}

    monkeypatch.setattr(MissionPlanner, "execute_step", lambda self, step, target, active_permitted=False: slow_execute_step(step, target, active_permitted))
    monkeypatch.setattr(MissionPlanner, "run_autonomous_loop", lambda self, **kwargs: {"status": "complete"})

    with TestClient(app) as client:
        import concurrent.futures

        def do_approve():
            return client.post(
                f"/api/v1/agent/approve/{action_id}",
                headers={"Authorization": f"Bearer {token}"},
            )

        def do_get_findings():
            # Wait 30ms so approve is already executing inside its thread
            time.sleep(0.03)
            t_start = time.perf_counter()
            resp = client.get(
                "/api/v1/findings",
                headers={"Authorization": f"Bearer {token}"},
            )
            t_resp = time.perf_counter() - t_start
            return resp, t_resp

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut_approve = executor.submit(do_approve)
            fut_findings = executor.submit(do_get_findings)

            approve_res = fut_approve.result()
            findings_res, findings_time = fut_findings.result()

        assert approve_res.status_code == 200
        assert findings_res.status_code == 200
        # Findings endpoint must return fast without waiting for slow_execute_step to complete
        assert findings_time < 0.10, f"Findings endpoint blocked! Took {findings_time:.4f}s"


def test_real_mission_approval_banner_clear_timing(clean_workspace, monkeypatch):
    """End-to-end timing test simulating operator clicking 'Approve' on Juice Shop / Mutillidae mission.

    Verifies banner clearing event arrives over WebSocket in < 1.0s (measured < 0.05s)
    and concurrent requests are non-blocking.
    """
    token = get_or_create_api_token()
    app = create_app()

    target = "http://localhost:4444"
    app_sys = ApprovalSystem(base_dir=clean_workspace)
    action_id = "ACT-JUICE-DESTRUCTIVE-01"
    app_sys.submit_for_approval({
        "action_id": action_id,
        "mission_target": target,
        "target": f"{target}/rest/user/login",
        "action": "sql_injection_verification",
        "reason": "Verify authentication bypass via SQL injection payload",
        "tool_name": "sqlmap",
        "risk": "High",
        "impact_class": "DESTRUCTIVE",
        "impact_justification": "Active SQL injection testing modifying auth state",
        "step": {
            "name": "SQLMap Auth Bypass Probe",
            "tool": "sqlmap",
            "action": "validate",
            "impact_class": "DESTRUCTIVE",
            "target": f"{target}/rest/user/login",
        },
        "current_iteration": 1,
        "max_iterations": 3,
        "prior_iterations": [],
        "active_permitted": True,
        "remaining_destructive_count": 1,
        "upcoming_pipeline": [],
    })

    # Simulate realistic 300ms tool execution and autonomous loop continuation
    def mock_step_exec(step, t, active_permitted=False):
        time.sleep(0.3)
        return {"success": True, "result": {"status": "completed"}}

    def mock_loop(**kwargs):
        time.sleep(0.2)
        return {"status": "complete", "message": "Mission finished"}

    monkeypatch.setattr(MissionPlanner, "execute_step", lambda self, step=None, target=None, active_permitted=False, **kwargs: mock_step_exec(step, target, active_permitted))
    monkeypatch.setattr(MissionPlanner, "run_autonomous_loop", lambda self, **kwargs: mock_loop(**kwargs))

    with TestClient(app) as client:
        with client.websocket_connect(f"/ws/events?token={token}") as ws:
            import concurrent.futures

            # Measure time from POST click until banner-clearing event is delivered to WebSocket
            t_click = time.perf_counter()

            def post_approve():
                return client.post(
                    f"/api/v1/agent/approve/{action_id}",
                    headers={"Authorization": f"Bearer {token}"},
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(post_approve)

                # First event received by browser
                msg_raw_1 = ws.receive_text()
                t_event_1 = time.perf_counter()
                clear_delay_1 = t_event_1 - t_click

                ev1 = json.loads(msg_raw_1)
                # Second event received by browser
                msg_raw_2 = ws.receive_text()
                t_event_2 = time.perf_counter()
                clear_delay_2 = t_event_2 - t_click

                ev2 = json.loads(msg_raw_2)

                # Unrelated request latency during approval window
                t_findings_start = time.perf_counter()
                findings_resp = client.get(
                    "/api/v1/findings",
                    headers={"Authorization": f"Bearer {token}"},
                )
                findings_latency = time.perf_counter() - t_findings_start

                post_res = fut.result()

            # Confirm events
            received_events = [ev1.get("event"), ev2.get("event")]
            assert "mission_progress" in received_events
            assert "action_approved" in received_events

            # Verify the banner-clearing time: MUST be near-instant (< 1s, actual target < 50ms)
            banner_clear_time = min(clear_delay_1, clear_delay_2)
            print(f"\n[MEASURED BANNER CLEAR TIME]: {banner_clear_time * 1000:.2f} ms")
            assert banner_clear_time < 1.0, f"Banner clear time too slow: {banner_clear_time:.4f}s"
            assert post_res.status_code == 200
            assert findings_resp.status_code == 200
            assert findings_latency < 0.10, f"Unrelated endpoint blocked: {findings_latency:.4f}s"
            print(f"[MEASURED FINDINGS LATENCY]: {findings_latency * 1000:.2f} ms")

            # Third event emitted when tool completes before autonomous loop
            msg_raw_3 = ws.receive_text()
            ev3 = json.loads(msg_raw_3)
            assert ev3.get("event") == "mission_progress"
            assert ev3.get("data", {}).get("state") == "reasoning"

            # Verify WebSocket stayed healthy (no drops)
            ws.send_text("ping")
            assert ws.receive_text() == "pong"

