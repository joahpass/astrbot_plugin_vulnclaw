"""Authentication helpers without a web-framework dependency."""

from __future__ import annotations

import base64
import secrets


def credentials_are_valid(
    authorization: str | None,
    expected_username: str,
    expected_password: str,
) -> bool:
    if not authorization or not authorization.startswith("Basic "):
        return False
    try:
        encoded = authorization.removeprefix("Basic ").strip()
        username, password = base64.b64decode(encoded, validate=True).decode("utf-8").split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return False
    return secrets.compare_digest(username, expected_username) and secrets.compare_digest(
        password, expected_password
    )
