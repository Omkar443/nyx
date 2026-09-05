"""
Pytest configuration for NYX test suite.
By default, enables deterministic LLM mocking (NYX_MOCK_LLM=1) so the full test suite
executes in ~15-20s rather than making real inference calls to local AI servers.
Pass --live-llm to run tests against the live local LLM server.
"""
from __future__ import annotations

import os
import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live-llm",
        action="store_true",
        default=False,
        help="Run tests with live LLM calls (disables NYX_MOCK_LLM=1 default).",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "live_llm: mark test as requiring live LLM inference"
    )
    # Default to mock mode unless --live-llm is explicitly passed
    if not config.getoption("--live-llm", default=False):
        os.environ["NYX_MOCK_LLM"] = "1"
    else:
        # User explicitly asked for live LLM, remove mock env var if set
        os.environ.pop("NYX_MOCK_LLM", None)


@pytest.fixture(autouse=True)
def _handle_live_llm_marker(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """If a test is marked with @pytest.mark.live_llm, unset NYX_MOCK_LLM for that test."""
    if request.node.get_closest_marker("live_llm"):
        monkeypatch.delenv("NYX_MOCK_LLM", raising=False)
