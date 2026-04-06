"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from iac_risk.web.config import WebConfig
from iac_risk.web.storage.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    config: WebConfig = app.state.config
    config.snapshots_dir.mkdir(parents=True, exist_ok=True)
    init_db(config.db_path)
    yield


def _api_key_middleware(app: FastAPI, config: WebConfig) -> None:
    """Add API key authentication for /api/* routes."""

    @app.middleware("http")
    async def check_api_key(request: Request, call_next: object) -> Response:
        if (
            config.api_key
            and request.url.path.startswith("/api/")
            and not request.url.path.startswith("/api/webhooks/")
        ):
            key = request.headers.get("X-API-Key", "")
            if key != config.api_key:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key"},
                )
        return await call_next(request)  # type: ignore[misc]


def create_app(config: WebConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    config = config or WebConfig()

    app = FastAPI(
        title="Pro-Prowler",
        version="0.1.0",
        description="NIST SP 800-30 based risk assessment for IaC",
        lifespan=lifespan,
    )
    app.state.config = config

    _api_key_middleware(app, config)

    from iac_risk.web.routes.assess import router as assess_router
    from iac_risk.web.routes.chat import router as chat_router
    from iac_risk.web.routes.dashboard import router as dashboard_router
    from iac_risk.web.routes.fix import router as fix_router
    from iac_risk.web.routes.governance import router as governance_router
    from iac_risk.web.routes.settings import router as settings_router
    from iac_risk.web.routes.snapshots import router as snapshots_router
    from iac_risk.web.routes.webhooks import router as webhooks_router

    app.include_router(assess_router, prefix="/api", tags=["assess"])
    app.include_router(snapshots_router, prefix="/api", tags=["snapshots"])
    app.include_router(webhooks_router, prefix="/api", tags=["webhooks"])
    app.include_router(fix_router, prefix="/api", tags=["fix"])
    app.include_router(chat_router, prefix="/api", tags=["chat"])
    app.include_router(governance_router, tags=["governance"])
    app.include_router(settings_router, tags=["settings"])
    app.include_router(dashboard_router, tags=["dashboard"])

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/")
    async def root():  # type: ignore[no-untyped-def]
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/dashboard")

    return app
