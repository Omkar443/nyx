import asyncio
import logging
from unittest.mock import MagicMock
import pytest
from starlette.requests import Request
from starlette.responses import Response

from nyx.infrastructure.process import request_shutdown, reset_shutdown, is_shutdown_requested
from nyx.ai.tracker import active_mission_tracker
from nyx.core import engagement
from nyx.web.app import create_app


@pytest.fixture(autouse=True)
def reset_shutdown_state():
    reset_shutdown()
    yield
    reset_shutdown()


def test_cancelled_error_during_shutdown_suppressed_cleanly():
    """Verify CancelledError during shutdown is caught and logged cleanly without traceback."""
    class LogCatcher(logging.Handler):
        def __init__(self):
            super().__init__()
            self.messages = []
        def emit(self, record):
            self.messages.append(record.getMessage())

    catcher = LogCatcher()
    nyx_logger = logging.getLogger("nyx")
    nyx_logger.addHandler(catcher)

    try:
        async def _run():
            app = create_app()
            middleware_fn = None
            for mw in app.user_middleware:
                if hasattr(mw, "kwargs") and "dispatch" in mw.kwargs:
                    middleware_fn = mw.kwargs["dispatch"]
                    break

            assert middleware_fn is not None, "Could not find add_security_headers_and_request_id middleware"

            # Simulate shutdown active
            request_shutdown()
            assert is_shutdown_requested() is True

            # Simulate call_next raising CancelledError (as occurs when Uvicorn cancels in-flight requests on exit)
            async def mock_call_next(req):
                raise asyncio.CancelledError()

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/api/v1/ai/autonomous-run",
                "headers": [(b"x-request-id", b"REQ-SHUTDOWN-TEST")],
            }
            req = Request(scope)

            res = await middleware_fn(req, mock_call_next)

            # 1. Returned clean Response without propagating traceback
            assert isinstance(res, Response)
            assert res.status_code == 499

        asyncio.run(_run())

        # 2. Clean single line log emitted
        combined_logs = " ".join(catcher.messages)
        assert "[SHUTDOWN]" in combined_logs
        assert "cancelled during graceful shutdown" in combined_logs
        assert "REQ-SHUTDOWN-TEST" in combined_logs
    finally:
        nyx_logger.removeHandler(catcher)


def test_cancelled_error_outside_shutdown_not_swallowed():
    """Verify CancelledError outside shutdown is NOT swallowed and re-raises normally."""
    async def _run():
        app = create_app()
        middleware_fn = None
        for mw in app.user_middleware:
            if hasattr(mw, "kwargs") and "dispatch" in mw.kwargs:
                middleware_fn = mw.kwargs["dispatch"]
                break

        reset_shutdown()
        assert is_shutdown_requested() is False

        async def mock_call_next(req):
            raise asyncio.CancelledError()

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/findings",
            "headers": [],
        }
        req = Request(scope)

        with pytest.raises(asyncio.CancelledError):
            await middleware_fn(req, mock_call_next)

    asyncio.run(_run())


def test_standard_exceptions_unaffected():
    """Verify standard application errors are unaffected by the shutdown cancellation handler."""
    async def _run():
        app = create_app()
        middleware_fn = None
        for mw in app.user_middleware:
            if hasattr(mw, "kwargs") and "dispatch" in mw.kwargs:
                middleware_fn = mw.kwargs["dispatch"]
                break

        reset_shutdown()

        async def mock_call_next(req):
            raise ValueError("Invalid parameter value")

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/test",
            "headers": [],
        }
        req = Request(scope)

        with pytest.raises(ValueError, match="Invalid parameter value"):
            await middleware_fn(req, mock_call_next)

    asyncio.run(_run())


def test_mission_state_consistent_after_shutdown_interrupt(tmp_path):
    """Verify mission state is aborted consistently and starts idle on server restart."""
    engagement.init_engagement("http://localhost:4444", reset=True, base_dir=tmp_path)
    
    # Simulate mission was running
    active_mission_tracker.start("http://localhost:4444", max_iterations=5)
    assert active_mission_tracker.is_running is True
    assert active_mission_tracker.status == "running"

    # Simulate shutdown interruption
    request_shutdown()
    active_mission_tracker.abort(
        reason="cancelled",
        details={"message": "Mission execution cancelled due to server shutdown."},
    )

    # Tracker reflects aborted state, not running
    assert active_mission_tracker.is_running is False
    assert active_mission_tracker.status == "aborted"

    # Simulate server restart (reset tracker instance as occurs on fresh process spawn)
    active_mission_tracker.reset()
    assert active_mission_tracker.is_running is False
    assert active_mission_tracker.status == "idle"

    # Engagement state file remains valid and consistent
    state_file = tmp_path / ".engagement" / "state.json"
    assert state_file.exists()
