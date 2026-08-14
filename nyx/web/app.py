"""
NYX FastAPI Web Application Core
"""
from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Request, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from nyx.web.auth import verify_ws_token, get_or_create_api_token
from nyx.web.events import ws_manager
from nyx.web.routes import ALL_ROUTERS
from nyx.web.schemas import HealthResponse, ErrorResponse, ErrorDetail


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern FastAPI lifespan context manager replacing deprecated on_event handlers."""
    from nyx.worker.daemon import WorkerDaemon
    daemon = WorkerDaemon(worker_id="WRK-WEB-DAEMON")
    app.state.worker_daemon = daemon
    daemon_task = asyncio.create_task(
        daemon.start_async_loop(poll_interval=1.0)
    )
    app.state.worker_daemon_task = daemon_task
    try:
        yield
    finally:
        daemon.stop()
        daemon_task.cancel()


def create_app() -> FastAPI:
    """Create and configure NYX FastAPI web application."""
    app = FastAPI(
        title="NYX Security Operations Dashboard API",
        description="Local web platform interface for NYX Security Intelligence Engine",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    # Restricted CORS configuration (never defaults to '*' for authenticated APIs)
    allowed_origins = [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]
    custom_origin = os.environ.get("NYX_ALLOWED_ORIGIN")
    if custom_origin:
        allowed_origins.append(custom_origin)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Token", "X-Request-ID"],
    )

    # Middleware for Correlation ID and Security Headers
    @app.middleware("http")
    async def add_security_headers_and_request_id(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or f"REQ-{uuid.uuid4().hex[:8].upper()}"
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    # Exception Handler: Structured JSON Error without Tracebacks
    @app.exception_handler(Exception)
    async def custom_global_exception_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", "REQ-UNKNOWN")
        err_detail = ErrorDetail(
            code="INTERNAL_ERROR",
            message="An internal server error occurred.",
            request_id=request_id,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(error=err_detail).dict(),
        )

    # Unauthenticated Health Endpoints
    @app.get("/health", response_model=HealthResponse, tags=["System"])
    @app.get("/api/v1/health", response_model=HealthResponse, tags=["System"])
    async def health_check() -> Dict[str, Any]:
        """Unauthenticated health check endpoint."""
        tok = get_or_create_api_token()
        return {
            "status": "ok",
            "version": "1.0.0",
            "app_name": "NYX Security Operations Dashboard",
            "workspace_active": True,
            "target": os.environ.get("NYX_TARGET", "example.com"),
            "authentication_enabled": bool(tok),
            "api_token": tok,
        }

    # Authenticated WebSocket Endpoint
    @app.websocket("/ws/events")
    async def websocket_events_endpoint(websocket: WebSocket, token: str = Query(None)):
        """Real-time event streaming WebSocket endpoint."""
        if not await verify_ws_token(token):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                # Optional ping/pong
                if data == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception:
            ws_manager.disconnect(websocket)

    # Include all API Routers
    for router in ALL_ROUTERS:
        app.include_router(router)

    # Static file mounting for frontend SPA if built assets exist
    frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    if frontend_dist.exists() and frontend_dist.is_dir():
        app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="static_assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str):
            if full_path.startswith("api/") or full_path.startswith("ws/") or full_path == "health":
                return JSONResponse(status_code=404, content={"detail": "Not Found"})
            file_p = frontend_dist / full_path
            if file_p.exists() and file_p.is_file():
                return FileResponse(file_p)
            return FileResponse(frontend_dist / "index.html")

    return app


app = create_app()
