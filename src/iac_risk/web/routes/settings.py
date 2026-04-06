"""Settings page — configurable assessment defaults."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader

from iac_risk.web.config import WebConfig
from iac_risk.web.storage.database import (
    get_all_settings,
    save_settings,
)

router = APIRouter()

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,
)


def _cfg(request: Request) -> WebConfig:
    return request.app.state.config


@router.get("/api/settings")
async def get_settings(request: Request) -> dict:
    config = _cfg(request)
    return get_all_settings(config.db_path)


@router.post("/api/settings")
async def update_settings(request: Request) -> dict:
    config = _cfg(request)
    body = await request.json()
    save_settings(config.db_path, body)
    return {"status": "saved"}


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    config = _cfg(request)
    settings = get_all_settings(config.db_path)
    template = _env.get_template("settings.html.j2")
    html = template.render(s=settings)
    return HTMLResponse(content=html)
