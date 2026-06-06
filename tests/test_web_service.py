from __future__ import annotations

import base64
from pathlib import Path

from web.auth import credentials_are_valid


ROOT = Path(__file__).resolve().parents[1]


def _basic(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def test_basic_auth_credentials() -> None:
    assert credentials_are_valid(_basic("admin", "strong-password"), "admin", "strong-password")
    assert not credentials_are_valid(_basic("admin", "wrong"), "admin", "strong-password")
    assert not credentials_are_valid(None, "admin", "strong-password")
    assert not credentials_are_valid("Bearer token", "admin", "strong-password")


def test_compose_exposes_authenticated_web_ui_without_docker_socket() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    web_service = compose.split("  vulnclaw-web:", 1)[1].split("\nnetworks:", 1)[0]
    assert '"1145:1145"' in web_service
    assert "VULNCLAW_WEB_PASSWORD" in web_service
    assert "/var/run/docker.sock" not in web_service
    assert "vulnclaw-web-data:/data" in web_service
    assert "read_only: true" in web_service
