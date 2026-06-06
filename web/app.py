"""Protect the upstream VulnClaw Web UI with HTTP Basic authentication."""

from __future__ import annotations

import os

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from vulnclaw.web.app import create_app
from web.auth import credentials_are_valid


def build_app():
    username = os.environ.get("VULNCLAW_WEB_USERNAME", "").strip()
    password = os.environ.get("VULNCLAW_WEB_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("VULNCLAW_WEB_USERNAME and VULNCLAW_WEB_PASSWORD are required")

    app = create_app()

    @app.middleware("http")
    async def require_basic_auth(request: Request, call_next):
        if request.url.path == "/healthz":
            return JSONResponse({"status": "ok", "service": "vulnclaw-web"})
        if not credentials_are_valid(request.headers.get("authorization"), username, password):
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="VulnClaw", charset="UTF-8"'},
            )
        return await call_next(request)

    return app


app = build_app()
