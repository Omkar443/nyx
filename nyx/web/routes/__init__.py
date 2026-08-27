"""
NYX Web API Router Package
"""
from __future__ import annotations

from nyx.web.routes.auth import router as auth_router
from nyx.web.routes.mission import router as mission_router
from nyx.web.routes.surface import router as surface_router
from nyx.web.routes.findings import router as findings_router
from nyx.web.routes.evidence import router as evidence_router
from nyx.web.routes.execution import router as execution_router
from nyx.web.routes.intelligence import router as intelligence_router
from nyx.web.routes.agent import router as agent_router
from nyx.web.routes.fleet import router as fleet_router
from nyx.web.routes.workers import router as workers_router
from nyx.web.routes.browser import router as browser_router
from nyx.web.routes.continuous import router as continuous_router
from nyx.web.routes.settings import router as settings_router
from nyx.web.routes.engine import router as engine_router

ALL_ROUTERS = [
    auth_router,
    mission_router,
    surface_router,
    findings_router,
    evidence_router,
    execution_router,
    intelligence_router,
    agent_router,
    fleet_router,
    workers_router,
    browser_router,
    continuous_router,
    settings_router,
    engine_router,
]

__all__ = ["ALL_ROUTERS"]
